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

impl TryFrom<TransactionMetadata> for RustTransactionMetadata {
    type Error = crate::MithrasCryptoError;

    fn try_from(meta: TransactionMetadata) -> Result<Self, Self::Error> {
        let sender_arr: [u8; 32] = meta
            .sender
            .as_slice()
            .try_into()
            .map_err(|_| crate::MithrasCryptoError::Error("sender must be 32 bytes".to_string()))?;
        let sender = ed25519_dalek::VerifyingKey::from_bytes(&sender_arr)
            .map_err(|e| crate::MithrasCryptoError::Error(format!("Invalid sender public key bytes: {}", e)))?;
        if meta.lease.len() != 32 {
            return Err(crate::MithrasCryptoError::Error(
                "lease must be 32 bytes".to_string(),
            ));
        }
        let mut lease = [0u8; 32];
        lease.copy_from_slice(&meta.lease[..32]);
        let network = match meta.network.as_str() {
            "mainnet" => mithras_crypto::hpke::SupportedNetwork::Mainnet,
            "testnet" => mithras_crypto::hpke::SupportedNetwork::Testnet,
            "betanet" => mithras_crypto::hpke::SupportedNetwork::Betanet,
            "devnet" => mithras_crypto::hpke::SupportedNetwork::Devnet,
            _ => mithras_crypto::hpke::SupportedNetwork::Custom([0u8; 32]),
        };
        Ok(RustTransactionMetadata {
            sender,
            first_valid: meta.first_valid,
            last_valid: meta.last_valid,
            lease,
            network,
            app_id: meta.app_id,
        })
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

impl TryFrom<HpkeEnvelope> for RustHpkeEnvelope {
    type Error = crate::MithrasCryptoError;

    fn try_from(env: HpkeEnvelope) -> Result<Self, Self::Error> {
        let encapsulated_key: [u8; 32] = env
            .encapsulated_key
            .as_slice()
            .try_into()
            .map_err(|_| crate::MithrasCryptoError::Error("encapsulated_key should be 32 bytes".to_string()))?;
        let ciphertext: [u8; mithras_crypto::hpke::CIPHER_TEXT_SIZE] = env
            .ciphertext
            .as_slice()
            .try_into()
            .map_err(|_| crate::MithrasCryptoError::Error("ciphertext should be CIPHER_TEXT_SIZE bytes".to_string()))?;
        let discovery_tag: [u8; 32] = env
            .discovery_tag
            .as_slice()
            .try_into()
            .map_err(|_| crate::MithrasCryptoError::Error("discovery_tag should be 32 bytes".to_string()))?;
        let suite = SupportedHpkeSuite::try_from(env.suite)
            .map_err(|_| crate::MithrasCryptoError::Error("invalid suite identifier".to_string()))?;

        Ok(RustHpkeEnvelope {
            version: env.version,
            suite,
            encapsulated_key,
            ciphertext,
            discovery_tag,
        })
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
