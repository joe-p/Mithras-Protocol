use mithras_crypto::hpke::HPKE_SIZE;
use mithras_crypto::hpke::HpkeEnvelope as RustHpkeEnvelope;
use mithras_crypto::hpke::SupportedHpkeSuite;
use mithras_crypto::hpke::TransactionMetadata as RustTransactionMetadata;

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
        let sender_arr: [u8; 32] =
            meta.sender.as_slice().try_into().map_err(|_| {
                crate::MithrasCryptoError::Error("sender must be 32 bytes".to_string())
            })?;
        let sender = ed25519_dalek::VerifyingKey::from_bytes(&sender_arr).map_err(|e| {
            crate::MithrasCryptoError::Error(format!("Invalid sender public key bytes: {}", e))
        })?;
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

#[derive(uniffi::Record)]
pub struct HpkeEnvelope {
    pub version: u8,
    pub suite: u8,
    pub encapsulated_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub discovery_tag: Vec<u8>,
    pub discovery_ephemeral: Vec<u8>,
}

impl TryFrom<HpkeEnvelope> for RustHpkeEnvelope {
    type Error = crate::MithrasCryptoError;

    fn try_from(env: HpkeEnvelope) -> Result<Self, Self::Error> {
        let encapsulated_key: [u8; 32] =
            env.encapsulated_key.as_slice().try_into().map_err(|_| {
                crate::MithrasCryptoError::Error("encapsulated_key should be 32 bytes".to_string())
            })?;
        let ciphertext: [u8; mithras_crypto::hpke::CIPHER_TEXT_SIZE] =
            env.ciphertext.as_slice().try_into().map_err(|_| {
                crate::MithrasCryptoError::Error(
                    "ciphertext should be CIPHER_TEXT_SIZE bytes".to_string(),
                )
            })?;
        let discovery_tag: [u8; 32] = env.discovery_tag.as_slice().try_into().map_err(|_| {
            crate::MithrasCryptoError::Error("discovery_tag should be 32 bytes".to_string())
        })?;
        let suite = SupportedHpkeSuite::try_from(env.suite).map_err(|_| {
            crate::MithrasCryptoError::Error("invalid suite identifier".to_string())
        })?;

        let discovery_ephemeral: [u8; 32] =
            env.discovery_ephemeral.as_slice().try_into().map_err(|_| {
                crate::MithrasCryptoError::Error(
                    "discovery_ephemeral should be 32 bytes".to_string(),
                )
            })?;

        Ok(RustHpkeEnvelope {
            version: env.version,
            suite,
            encapsulated_key,
            ciphertext,
            discovery_tag,
            discovery_ephemeral,
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
            discovery_ephemeral: env.discovery_ephemeral.to_vec(),
        }
    }
}

#[uniffi::export]
pub fn encode_hpke_envelope(envelope: HpkeEnvelope) -> Result<Vec<u8>, crate::MithrasCryptoError> {
    let rust_envelope: RustHpkeEnvelope = envelope.try_into()?;
    Ok(rust_envelope.as_bytes().to_vec())
}

#[uniffi::export]
pub fn decode_hpke_envelope(data: Vec<u8>) -> Result<HpkeEnvelope, crate::MithrasCryptoError> {
    let arr: [u8; HPKE_SIZE] = data.try_into().map_err(|_| {
        crate::MithrasCryptoError::Error("data must be exactly 256 bytes".to_string())
    })?;
    let rust_envelope = RustHpkeEnvelope::from_bytes(&arr).map_err(|e| {
        crate::MithrasCryptoError::Error(format!("Failed to decode HpkeEnvelope: {}", e))
    })?;
    Ok(rust_envelope.into())
}
