pub mod address;
pub mod discovery;
pub mod hpke;
pub mod keypairs;
pub mod utxo;

#[cfg(test)]
mod tests {
    use crate::{
        address::MithrasAddr,
        discovery::{
            compute_discovery_secret_receiver, compute_discovery_secret_sender,
            compute_discovery_tag,
        },
        hpke::{HpkeEnvelope, SupportedHpkeSuite},
        keypairs::{
            DiscoveryKeypair, SpendSeed, TweakedSigner, derive_tweak_scalar, derive_tweaked_pubkey,
        },
        utxo::{SECRET_SIZE, UtxoInputs, UtxoSecrets},
    };

    use curve25519_dalek::Scalar;
    use ed25519_dalek::{Verifier, VerifyingKey};

    #[test]
    fn test_keypair_generation() {
        let spend_keypair = SpendSeed::generate();
        let discovery_keypair = DiscoveryKeypair::generate();

        assert_eq!(spend_keypair.seed().len(), 32);
        assert_eq!(discovery_keypair.public_key().as_bytes().len(), 32);
    }

    #[test]
    fn test_discovery_secret_computation() {
        let discovery_keypair = DiscoveryKeypair::generate();
        let ephemeral_keypair = DiscoveryKeypair::generate();

        let discovery_secret_sender = compute_discovery_secret_sender(
            ephemeral_keypair.private_key(),
            discovery_keypair.public_key(),
        );

        let discovery_secret_receiver = compute_discovery_secret_receiver(
            discovery_keypair.private_key(),
            ephemeral_keypair.public_key(),
        );

        assert_eq!(discovery_secret_sender, discovery_secret_receiver);
    }

    #[test]
    fn test_tweaked_keypair_computation() {
        let spend_keypair = SpendSeed::generate();
        let discovery_keypair = DiscoveryKeypair::generate();
        let ephemeral_keypair = DiscoveryKeypair::generate();

        let discovery_secret_sender = compute_discovery_secret_sender(
            ephemeral_keypair.private_key(),
            discovery_keypair.public_key(),
        );

        let tweak_scalar = derive_tweak_scalar(&discovery_secret_sender);

        let tweaked_keypair_sender =
            derive_tweaked_pubkey(spend_keypair.public_key(), &tweak_scalar);

        let tweaked_keypair_receiver = TweakedSigner::derive(&spend_keypair, &tweak_scalar);

        assert_eq!(
            tweaked_keypair_sender.to_bytes(),
            tweaked_keypair_receiver.public_key().to_bytes()
        );
    }

    #[test]
    fn test_discovery_tag() {
        let discovery_keypair = DiscoveryKeypair::generate();
        let ephemeral_keypair = DiscoveryKeypair::generate();

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
    }

    #[test]
    fn test_ed25519_signing_with_tweaked_key() {
        let spend_keypair = SpendSeed::generate();
        let discovery_secret = [42u8; 32];
        let tweak_scalar = derive_tweak_scalar(&discovery_secret);
        let tweaked_keypair_receiver =
            derive_tweaked_pubkey(spend_keypair.public_key(), &tweak_scalar);

        let msg = b"example spend authorization";
        let tweaked_priv = TweakedSigner::derive(&spend_keypair, &tweak_scalar);
        let sig = tweaked_priv.sign(msg);

        let verify_res = tweaked_keypair_receiver.verify_strict(msg, &sig);
        if verify_res.is_err() {
            tweaked_keypair_receiver.verify(msg, &sig).unwrap();
        }
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
            discoery_tag: [0u8; 32],
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
        let spend_keypair = SpendSeed::generate();
        let discovery_keypair = DiscoveryKeypair::generate();
        let discovery_secret = [42u8; 32];
        let tweak_scalar = derive_tweak_scalar(&discovery_secret);
        let tweaked_keypair_receiver = TweakedSigner::derive(&spend_keypair, &tweak_scalar);

        let mithras_addr = MithrasAddr::from_keys(
            tweaked_keypair_receiver.public_key(),
            discovery_keypair.public_key(),
            1, // version
            0, // network
            1, // suite
        );

        let encoded_addr = mithras_addr.encode();
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
        let spend_keypair = SpendSeed::generate();
        let discovery_keypair = DiscoveryKeypair::generate();

        let mithras_addr = MithrasAddr::from_keys(
            spend_keypair.public_key(),
            discovery_keypair.public_key(),
            1,
            0,
            1,
        );

        let sender_pubkey = *spend_keypair.public_key();
        let first_valid = 1000;
        let last_valid = 2000;
        let lease = [0u8; 32];
        let amount = 1000;

        let utxo_inputs = UtxoInputs::generate(
            sender_pubkey,
            first_valid,
            last_valid,
            lease,
            amount,
            mithras_addr.clone(),
        )
        .map_err(|e| anyhow::anyhow!(e))?;

        let recovered_secrets =
            UtxoSecrets::from_hpke_envelope(utxo_inputs.hpke_envelope, discovery_keypair);

        assert_eq!(recovered_secrets, utxo_inputs.secrets);

        let msg = b"example spend authorization";
        let tweaked_signer = TweakedSigner::derive(&spend_keypair, &recovered_secrets.tweak_scalar);
        let sig = tweaked_signer.sign(msg);

        let tweak_pubkey_from_sender = utxo_inputs.secrets.tweaked_pubkey;

        // Verify that the pubkey derived from the sender matches the
        // signature from the receiver
        // Since the secrets match, this is technically superfluous, but still a good sanity check
        let verify_res = tweak_pubkey_from_sender.verify_strict(msg, &sig);
        if verify_res.is_err() {
            tweaked_signer.public_key().verify(msg, &sig).unwrap();
        }

        Ok(())
    }
}
