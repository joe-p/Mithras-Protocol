use mithras_crypto::address::MithrasAddr as RustMithrasAddr;
use mithras_crypto::hpke::{
    SupportedHpkeSuite as RustSupportedHpkeSuite, SupportedNetwork as RustSupportedNetwork,
};

use ed25519_dalek::VerifyingKey as Ed25519PublicKey;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::MithrasCryptoError;

#[derive(uniffi::Object)]
pub struct MithrasAddr {
    pub rust: RustMithrasAddr,
}

#[uniffi::export]
impl MithrasAddr {
    pub fn encode(&self) -> Result<String, MithrasCryptoError> {
        self
            .rust
            .encode()
            .map_err(|e| MithrasCryptoError::Error(e.to_string()))
    }

    #[uniffi::constructor]
    pub fn decode(s: &str) -> Result<Self, MithrasCryptoError> {
        match RustMithrasAddr::decode(s) {
            Ok(addr) => Ok(MithrasAddr { rust: addr }),
            Err(e) => Err(MithrasCryptoError::Error(e.to_string())),
        }
    }

    #[uniffi::constructor]
    pub fn from_keys(
        ed25519_spend_pubkey: Vec<u8>,
        x25519_discovery_pubkey: Vec<u8>,
        version: u8,
        network: String,
        suite: u8,
    ) -> Result<Self, MithrasCryptoError> {
        let spend_arr: [u8; 32] = ed25519_spend_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| MithrasCryptoError::Error("Invalid Ed25519 public key length".to_string()))?;
        let disc_arr: [u8; 32] = x25519_discovery_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| MithrasCryptoError::Error("Invalid X25519 public key length".to_string()))?;

        let spend_pubkey = Ed25519PublicKey::from_bytes(&spend_arr)
            .map_err(|e| MithrasCryptoError::Error(format!("Invalid Ed25519 public key: {}", e)))?;
        let disc_pubkey = X25519PublicKey::from(disc_arr);

        let network_enum = match network.to_lowercase().as_str() {
            "mainnet" => RustSupportedNetwork::Mainnet,
            "testnet" => RustSupportedNetwork::Testnet,
            "netanet" => RustSupportedNetwork::Betanet,
            "devnet" => RustSupportedNetwork::Devnet,
            "custom" => RustSupportedNetwork::Custom([0u8; 32]),
            _ => return Err(MithrasCryptoError::Error("Unsupported network".to_string())),
        };

        let suite_enum = match suite {
            0 => RustSupportedHpkeSuite::Base25519Sha512ChaCha20Poly1305,
            _ => return Err(MithrasCryptoError::Error("Unsupported HPKE suite".to_string())),
        };

        Ok(Self {
            rust: RustMithrasAddr::from_keys(
                &spend_pubkey,
                &disc_pubkey,
                version,
                network_enum,
                suite_enum,
            ),
        })
    }
}
