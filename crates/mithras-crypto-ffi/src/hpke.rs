use mithras_crypto::hpke::HpkeEnvelope as RustHpkeEnvelope;
use mithras_crypto::hpke::SupportedHpkeSuite;
use mithras_crypto::hpke::TransactionMetadata as RustTransactionMetadata;

// pub struct TransactionMetadata {
//     pub sender: Ed25519PublicKey,
//     pub first_valid: u64,
//     pub last_valid: u64,
//     pub lease: [u8; 32],
//     pub network: SupportedNetwork,
//     pub app_id: u64,
// }

#[derive(uniffi::Record)]
pub struct TransactionMetadata {
    pub sender: Vec<u8>,
    pub first_valid: u64,
    pub last_valid: u64,
    pub lease: Vec<u8>,
    pub network: String,
    pub app_id: u64,
}

impl From<TransactionMetadata> for RustTransactionMetadata {
    fn from(meta: TransactionMetadata) -> Self {
        let sender = ed25519_dalek::VerifyingKey::from_bytes(
            &meta.sender.try_into().expect("should be 32 bytes"),
        )
        .expect("Invalid sender public key bytes");
        let mut lease = [0u8; 32];
        lease.copy_from_slice(&meta.lease[..32]);
        let network = match meta.network.as_str() {
            "mainnet" => mithras_crypto::hpke::SupportedNetwork::Mainnet,
            "testnet" => mithras_crypto::hpke::SupportedNetwork::Testnet,
            "betanet" => mithras_crypto::hpke::SupportedNetwork::Betanet,
            "devnet" => mithras_crypto::hpke::SupportedNetwork::Devnet,
            _ => mithras_crypto::hpke::SupportedNetwork::Custom([0u8; 32]), // Placeholder for custom networks
        };
        RustTransactionMetadata {
            sender,
            first_valid: meta.first_valid,
            last_valid: meta.last_valid,
            lease,
            network,
            app_id: meta.app_id,
        }
    }
}

// pub struct HpkeEnvelope {
//     /// The mithras version which determines the shape of the data in the plaintext
//     pub version: u8,
//     /// The HPKE suite identifier
//     pub suite: SupportedHpkeSuite,
//     pub encapsulated_key: [u8; 32],
//     #[serde(
//         serialize_with = "serialize_ciphertext",
//         deserialize_with = "deserialize_ciphertext"
//     )]
//     pub ciphertext: [u8; CIPHER_TEXT_SIZE],
//     pub discovery_tag: [u8; 32],
// }

#[derive(uniffi::Record)]
pub struct HpkeEnvelope {
    pub version: u8,
    pub suite: u8,
    pub encapsulated_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub discovery_tag: Vec<u8>,
}

impl From<HpkeEnvelope> for RustHpkeEnvelope {
    fn from(env: HpkeEnvelope) -> Self {
        let encapsulated_key: [u8; 32] = env
            .encapsulated_key
            .try_into()
            .expect("encapsulated_key should be 32 bytes");
        let ciphertext: [u8; mithras_crypto::hpke::CIPHER_TEXT_SIZE] = env
            .ciphertext
            .try_into()
            .expect("ciphertext should be CIPHER_TEXT_SIZE bytes");
        let discovery_tag: [u8; 32] = env
            .discovery_tag
            .try_into()
            .expect("discovery_tag should be 32 bytes");
        let suite = SupportedHpkeSuite::try_from(env.suite).expect("invalid suite identifier");

        RustHpkeEnvelope {
            version: env.version,
            suite,
            encapsulated_key,
            ciphertext,
            discovery_tag,
        }
    }
}

impl From<RustHpkeEnvelope> for HpkeEnvelope {
    fn from(env: RustHpkeEnvelope) -> Self {
        HpkeEnvelope {
            version: env.version,
            suite: env.suite.into(),
            encapsulated_key: env.encapsulated_key.to_vec(),
            ciphertext: env.ciphertext.to_vec(),
            discovery_tag: env.discovery_tag.to_vec(),
        }
    }
}
