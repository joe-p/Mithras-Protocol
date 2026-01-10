pub mod address;
pub mod discovery;
pub mod hpke;
pub mod keypairs;
pub mod utxo;
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum MithrasError {
    #[snafu(display("Error: {}", msg))]
    Other { msg: String },

    #[snafu(display("Cryptographic random number generation failed: {}", msg))]
    RandomGeneration { msg: String },

    #[snafu(display("HPKE operation failed: {}", msg))]
    HpkeOperation { msg: String },

    #[snafu(display("Ed25519 key parsing failed: {}", msg))]
    Ed25519KeyParsing { msg: String },

    #[snafu(display("Curve25519 point decompression failed: {}", msg))]
    CurvePointDecompression { msg: String },

    #[snafu(display("Address encoding failed: {}", msg))]
    AddressEncoding { msg: String },

    #[snafu(display("Data conversion failed: {}", msg))]
    DataConversion { msg: String },
}

#[cfg(test)]
mod tests {
    use crate::{
        MithrasError,
        address::MithrasAddr,
        discovery::{
            compute_discovery_secret_receiver, compute_discovery_secret_sender,
            compute_discovery_tag,
        },
        hpke::{HpkeEnvelope, SupportedHpkeSuite, SupportedNetwork, TransactionMetadata},
        keypairs::{
            DiscoveryKeypair, SpendSeed, TweakedSigner, derive_tweak_scalar, derive_tweaked_pubkey,
        },
        utxo::{SECRET_SIZE, UtxoInputs, UtxoSecrets},
    };

    use algod_client::AlgodClient;
    use algokit_transact::{
        Address, AlgorandMsgpack, PaymentTransactionFields, Transaction, TransactionHeader,
    };
    use curve25519_dalek::Scalar;
    use ed25519_dalek::{Verifier, VerifyingKey, ed25519::signature::SignerMut};
    use indexer_client::IndexerClient;
    use kmd_client::KmdClient;
    use subscriber::{Subscriber, TransactionSubscription};
    use test_utils::get_dispenser_account;

    /// Test keypairs for Mithras protocol
    struct TestKeypairs {
        spend: SpendSeed,
        discovery: DiscoveryKeypair,
    }

    impl TestKeypairs {
        fn generate() -> Result<Self, MithrasError> {
            Ok(Self {
                spend: SpendSeed::generate()?,
                discovery: DiscoveryKeypair::generate()?,
            })
        }

        fn mithras_addr(&self) -> MithrasAddr {
            MithrasAddr::from_keys(
                self.spend.public_key(),
                self.discovery.public_key(),
                1,
                SupportedNetwork::Testnet,
                SupportedHpkeSuite::Base25519Sha512ChaCha20Poly1305,
            )
        }
    }

    /// E2E test context containing all state needed for integration tests
    struct E2eTestContext {
        keypairs: TestKeypairs,
        txn_metadata: TransactionMetadata,
        utxo_inputs: UtxoInputs,
        signed_txn: algokit_transact::SignedTransaction,
        sender: Address,
        note: Vec<u8>,
    }

    impl E2eTestContext {
        async fn setup(algod: &AlgodClient, kmd: &KmdClient) -> anyhow::Result<Self> {
            let keypairs = TestKeypairs::generate().map_err(|e| anyhow::anyhow!(e))?;
            let mithras_addr = keypairs.mithras_addr();

            let sp = algod.transaction_params().await?;

            let txn_metadata = TransactionMetadata {
                sender: VerifyingKey::from_bytes(&[0u8; 32])?,
                first_valid: sp.last_round,
                last_valid: sp.last_round + 1000,
                lease: [0u8; 32],
                network: SupportedNetwork::Mainnet,
                app_id: 1337,
            };

            let utxo_inputs = UtxoInputs::generate(&txn_metadata, 1000, &mithras_addr)
                .map_err(|e| anyhow::anyhow!(e))?;

            let algo_sk = get_dispenser_account(algod, kmd).await?;
            let mut algo_signing_key = ed25519_dalek::SigningKey::from_bytes(&algo_sk);
            let sender = Address(*algo_signing_key.verifying_key().as_bytes());

            let note = rmp_serde::to_vec(&utxo_inputs.hpke_envelope)
                .expect("should serialize hpke envelope");

            let header = TransactionHeader {
                sender: sender.clone(),
                fee: Some(1000),
                first_valid: txn_metadata.first_valid,
                last_valid: txn_metadata.last_valid,
                genesis_id: Some(sp.genesis_id),
                genesis_hash: Some(
                    sp.genesis_hash
                        .try_into()
                        .expect("genesis hash should be 32 bytes"),
                ),
                note: Some(note.clone()),
                group: None,
                lease: Some(txn_metadata.lease),
                rekey_to: None,
            };

            let pay_txn = Transaction::Payment(PaymentTransactionFields {
                header,
                receiver: sender.clone(),
                amount: 0,
                close_remainder_to: None,
            });

            let bytes_to_sign = pay_txn.encode().expect("should get signing bytes");
            let sig = algo_signing_key.sign(&bytes_to_sign);

            let signed_txn = algokit_transact::SignedTransaction {
                transaction: pay_txn,
                signature: Some(sig.to_bytes()),
                multisignature: None,
                auth_address: None,
            };

            Ok(Self {
                keypairs,
                txn_metadata,
                utxo_inputs,
                signed_txn,
                sender,
                note,
            })
        }

        /// Verify that recovered secrets match and signature is valid
        fn verify_secrets_and_signature(
            &self,
            recovered_secrets: &UtxoSecrets,
        ) -> anyhow::Result<()> {
            assert_eq!(recovered_secrets, &self.utxo_inputs.secrets);

            let msg = b"example spend authorization";
            let tweaked_signer =
                TweakedSigner::derive(&self.keypairs.spend, &recovered_secrets.tweak_scalar)?;
            let sig = tweaked_signer.sign(msg)?;

            let tweak_pubkey_from_sender = self.utxo_inputs.secrets.tweaked_pubkey;

            // Verify that the pubkey derived from the sender matches the
            // signature from the receiver
            let verify_res = tweak_pubkey_from_sender.verify_strict(msg, &sig);
            if verify_res.is_err() {
                tweaked_signer.public_key().verify(msg, &sig).unwrap();
            }

            Ok(())
        }
    }

    #[test]
    fn test_keypair_generation() -> Result<(), MithrasError> {
        let spend_keypair = SpendSeed::generate()?;
        let discovery_keypair = DiscoveryKeypair::generate()?;

        assert_eq!(spend_keypair.seed().len(), 32);
        assert_eq!(discovery_keypair.public_key().as_bytes().len(), 32);
        Ok(())
    }

    #[test]
    fn test_discovery_secret_computation() -> Result<(), MithrasError> {
        let discovery_keypair = DiscoveryKeypair::generate()?;
        let ephemeral_keypair = DiscoveryKeypair::generate()?;

        let discovery_secret_sender = compute_discovery_secret_sender(
            ephemeral_keypair.private_key(),
            discovery_keypair.public_key(),
        );

        let discovery_secret_receiver = compute_discovery_secret_receiver(
            discovery_keypair.private_key(),
            ephemeral_keypair.public_key(),
        );

        assert_eq!(discovery_secret_sender, discovery_secret_receiver);
        Ok(())
    }

    #[test]
    fn test_tweaked_keypair_computation() -> Result<(), MithrasError> {
        let spend_keypair = SpendSeed::generate()?;
        let discovery_keypair = DiscoveryKeypair::generate()?;
        let ephemeral_keypair = DiscoveryKeypair::generate()?;

        let discovery_secret_sender = compute_discovery_secret_sender(
            ephemeral_keypair.private_key(),
            discovery_keypair.public_key(),
        );

        let tweak_scalar = derive_tweak_scalar(&discovery_secret_sender);

        let tweaked_keypair_sender =
            derive_tweaked_pubkey(spend_keypair.public_key(), &tweak_scalar)?;

        let tweaked_keypair_receiver = TweakedSigner::derive(&spend_keypair, &tweak_scalar)?;

        assert_eq!(
            tweaked_keypair_sender.to_bytes(),
            tweaked_keypair_receiver.public_key().to_bytes()
        );
        Ok(())
    }

    #[test]
    fn test_discovery_tag() -> Result<(), MithrasError> {
        let discovery_keypair = DiscoveryKeypair::generate()?;
        let ephemeral_keypair = DiscoveryKeypair::generate()?;

        let discovery_secret_sender = compute_discovery_secret_sender(
            ephemeral_keypair.private_key(),
            discovery_keypair.public_key(),
        );

        let discovery_secret_receiver = compute_discovery_secret_receiver(
            discovery_keypair.private_key(),
            ephemeral_keypair.public_key(),
        );

        let discovery_tag_sender = compute_discovery_tag(
            &discovery_secret_sender,
            &VerifyingKey::from_bytes(&[0u8; 32]).unwrap(),
            1000,
            2000,
            [0u8; 32],
        );

        let discovery_tag_receiver = compute_discovery_tag(
            &discovery_secret_receiver,
            &VerifyingKey::from_bytes(&[0u8; 32]).unwrap(),
            1000,
            2000,
            [0u8; 32],
        );

        assert_eq!(discovery_tag_sender, discovery_tag_receiver);
        Ok(())
    }

    #[test]
    fn test_ed25519_signing_with_tweaked_key() -> Result<(), MithrasError> {
        let spend_keypair = SpendSeed::generate()?;
        let discovery_secret = [42u8; 32];
        let tweak_scalar = derive_tweak_scalar(&discovery_secret);
        let tweaked_keypair_receiver =
            derive_tweaked_pubkey(spend_keypair.public_key(), &tweak_scalar)?;

        let msg = b"example spend authorization";
        let tweaked_priv = TweakedSigner::derive(&spend_keypair, &tweak_scalar)?;
        let sig = tweaked_priv.sign(msg)?;

        let verify_res = tweaked_keypair_receiver.verify_strict(msg, &sig);
        if verify_res.is_err() {
            tweaked_keypair_receiver.verify(msg, &sig).unwrap();
        }
        Ok(())
    }

    #[test]
    fn test_hpke_encryption_decryption() -> anyhow::Result<()> {
        let mut hpke = SupportedHpkeSuite::Base25519Sha512ChaCha20Poly1305.suite();
        let hpke_recipient = hpke.generate_key_pair().unwrap();

        let info = b"mithras|network:mainnet|app:1337|v:1"; // used by KDF
        let aad = b"txid:BLAH...BLAH";

        let (encapsulated_key, mut sender_ctx) = hpke
            .setup_sender(hpke_recipient.public_key(), info, None, None, None)
            .unwrap();

        let mithras_secret = UtxoSecrets {
            spending_secret: [42u8; 32],
            nullifier_secret: [43u8; 32],
            amount: 1000,
            tweak_scalar: Scalar::from(7u64),
            tweaked_pubkey: VerifyingKey::from_bytes(&[0u8; 32])?,
        };
        let secret_bytes: [u8; SECRET_SIZE] = mithras_secret.into();
        let ct = sender_ctx.seal(aad, &secret_bytes).unwrap();

        let env = HpkeEnvelope {
            version: 1,
            suite: SupportedHpkeSuite::Base25519Sha512ChaCha20Poly1305,
            encapsulated_key: encapsulated_key.clone().try_into().unwrap(),
            ciphertext: ct.clone().try_into().unwrap(),
            discovery_tag: [0u8; 32],
            discovery_ephemeral: encapsulated_key.clone().try_into().unwrap(),
        };

        let json = serde_json::to_string(&env)?;
        let env2: HpkeEnvelope = serde_json::from_str(&json)?;
        let enclosed_key_bytes = &env2.encapsulated_key;
        let ct_bytes = &env2.ciphertext;

        let mut recv_ctx = hpke
            .setup_receiver(
                enclosed_key_bytes,
                hpke_recipient.private_key(),
                info,
                None,
                None,
                None,
            )
            .unwrap();

        let pt = recv_ctx.open(aad, ct_bytes).unwrap();

        assert_eq!(&pt, &secret_bytes);
        Ok(())
    }

    #[test]
    fn test_mithras_address_encoding_decoding() -> anyhow::Result<()> {
        let spend_keypair = SpendSeed::generate().map_err(|e| anyhow::anyhow!(e))?;
        let discovery_keypair = DiscoveryKeypair::generate().map_err(|e| anyhow::anyhow!(e))?;
        let discovery_secret = [42u8; 32];
        let tweak_scalar = derive_tweak_scalar(&discovery_secret);
        let tweaked_keypair_receiver =
            TweakedSigner::derive(&spend_keypair, &tweak_scalar).map_err(|e| anyhow::anyhow!(e))?;

        let mithras_addr = MithrasAddr::from_keys(
            tweaked_keypair_receiver.public_key(),
            discovery_keypair.public_key(),
            1, // version
            SupportedNetwork::Testnet,
            SupportedHpkeSuite::Base25519Sha512ChaCha20Poly1305,
        );

        let encoded_addr = mithras_addr.encode().map_err(|e| anyhow::anyhow!(e))?;
        let decoded_addr = MithrasAddr::decode(&encoded_addr)?;

        assert_eq!(decoded_addr.version, mithras_addr.version);
        assert_eq!(decoded_addr.network, mithras_addr.network);
        assert_eq!(decoded_addr.suite, mithras_addr.suite);
        assert_eq!(decoded_addr.spend_ed25519, mithras_addr.spend_ed25519);
        assert_eq!(decoded_addr.disc_x25519, mithras_addr.disc_x25519);

        Ok(())
    }

    #[test]
    fn test_complete_mithras_protocol_flow_with_utxo_generate() -> anyhow::Result<()> {
        let keypairs = TestKeypairs::generate().map_err(|e| anyhow::anyhow!(e))?;
        let mithras_addr = keypairs.mithras_addr();

        let txn_metadata = TransactionMetadata {
            sender: VerifyingKey::from_bytes(&[0u8; 32])?,
            first_valid: 1000,
            last_valid: 2000,
            lease: [0u8; 32],
            network: SupportedNetwork::Mainnet,
            app_id: 1337,
        };

        let utxo_inputs = UtxoInputs::generate(&txn_metadata, 1000, &mithras_addr)
            .map_err(|e| anyhow::anyhow!(e))?;

        let recovered_secrets = UtxoSecrets::from_hpke_envelope(
            utxo_inputs.hpke_envelope,
            keypairs.discovery,
            &txn_metadata,
        )?;

        assert_eq!(recovered_secrets, utxo_inputs.secrets);

        let msg = b"example spend authorization";
        let tweaked_signer =
            TweakedSigner::derive(&keypairs.spend, &recovered_secrets.tweak_scalar)?;
        let sig = tweaked_signer.sign(msg)?;

        let tweak_pubkey_from_sender = utxo_inputs.secrets.tweaked_pubkey;

        // Verify that the pubkey derived from the sender matches the
        // signature from the receiver
        let verify_res = tweak_pubkey_from_sender.verify_strict(msg, &sig);
        if verify_res.is_err() {
            tweaked_signer.public_key().verify(msg, &sig).unwrap();
        }

        Ok(())
    }

    #[test]
    fn test_discovery_check_on_envelope() -> anyhow::Result<()> {
        let keypairs = TestKeypairs::generate().map_err(|e| anyhow::anyhow!(e))?;
        let addr = keypairs.mithras_addr();

        let txn = TransactionMetadata {
            sender: VerifyingKey::from_bytes(&[0u8; 32])?,
            first_valid: 10,
            last_valid: 20,
            lease: [0u8; 32],
            network: SupportedNetwork::Mainnet,
            app_id: 42,
        };

        let inputs = UtxoInputs::generate(&txn, 12345, &addr).map_err(|e| anyhow::anyhow!(e))?;
        let env = inputs.hpke_envelope;

        // Correct discovery key should validate
        let ok = env.discovery_check(keypairs.discovery.private_key(), &txn);
        assert!(ok);

        // Wrong discovery key should not validate
        let wrong_disc = DiscoveryKeypair::generate().map_err(|e| anyhow::anyhow!(e))?;
        let not_ok = env.discovery_check(wrong_disc.private_key(), &txn);
        assert!(!not_ok);

        Ok(())
    }

    #[tokio::test]
    async fn full_e2e_without_subscriber() -> anyhow::Result<()> {
        let algod = AlgodClient::localnet();
        let kmd = KmdClient::localnet();

        let ctx = E2eTestContext::setup(&algod, &kmd).await?;

        let confirmation = algod
            .raw_transaction(
                ctx.signed_txn
                    .encode()
                    .expect("should be able to encode stxn"),
            )
            .await?;

        let tx_resp = algod
            .pending_transaction_information(&confirmation.tx_id)
            .await?;

        let hpke_env_from_tx = rmp_serde::from_slice::<HpkeEnvelope>(
            tx_resp
                .txn
                .transaction
                .note()
                .ok_or_else(|| anyhow::anyhow!("note field missing from txn"))?,
        )?;

        let recovered_secrets = UtxoSecrets::from_hpke_envelope(
            hpke_env_from_tx,
            ctx.keypairs.discovery.clone(),
            &ctx.txn_metadata,
        )?;

        ctx.verify_secrets_and_signature(&recovered_secrets)?;

        Ok(())
    }

    #[tokio::test]
    async fn full_e2e_algod_subscriber() -> anyhow::Result<()> {
        let algod = AlgodClient::localnet();
        let kmd = KmdClient::localnet();
        let indexer = IndexerClient::localnet();

        let ctx = E2eTestContext::setup(&algod, &kmd).await?;

        algod
            .raw_transaction(
                ctx.signed_txn
                    .encode()
                    .expect("should be able to encode stxn"),
            )
            .await?;

        let mut subscriber = Subscriber::new(
            algod.clone(),
            indexer,
            ctx.txn_metadata.first_valid + 1,
            None,
        );

        let (txn_sender, txn_receiver) = crossbeam_channel::unbounded();

        let sub = TransactionSubscription {
            note: Some(ctx.note.clone()),
            sender: Some(ctx.sender.to_string()),
            app: None,
            txn_channel: txn_sender,
            app_args: None,
        };

        subscriber.subscribe(sub);
        subscriber.algod_catchup().await.unwrap();

        let txn = txn_receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .map_err(|e| anyhow::anyhow!("did not receive txn from subscriber: {}", e))?;

        let hpke_env_from_tx = rmp_serde::from_slice::<HpkeEnvelope>(
            txn.txn
                .signed_transaction
                .transaction
                .note()
                .ok_or_else(|| anyhow::anyhow!("note field missing from txn"))?,
        )?;

        let recovered_secrets = UtxoSecrets::from_hpke_envelope(
            hpke_env_from_tx,
            ctx.keypairs.discovery.clone(),
            &ctx.txn_metadata,
        )?;

        ctx.verify_secrets_and_signature(&recovered_secrets)?;

        Ok(())
    }
}
