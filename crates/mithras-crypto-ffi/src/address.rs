use mithras_crypto::address::MithrasAddr as RustMithrasAddr;
use mithras_crypto::hpke::{
    SupportedHpkeSuite as RustSupportedHpkeSuite, SupportedNetwork as RustSupportedNetwork,
};

use ed25519_dalek::VerifyingKey as Ed25519PublicKey;
use x25519_dalek::PublicKey as X25519PublicKey;

#[derive(uniffi::Object)]
pub struct MithrasAddr {
    pub rust: RustMithrasAddr,
}

#[uniffi::export]
impl MithrasAddr {
    pub fn encode(&self) -> String {
        self.rust.encode()
    }

    #[uniffi::constructor]
    pub fn decode(s: &str) -> Result<Self, String> {
        match RustMithrasAddr::decode(s) {
            Ok(addr) => Ok(MithrasAddr { rust: addr }),
            Err(e) => Err(format!("Failed to decode address: {}", e)),
        }
    }

    #[uniffi::constructor]
    pub fn from_keys(
        ed25519_spend_pubkey: Vec<u8>,
        x25519_discovery_pubkey: Vec<u8>,
        version: u8,
        network: String,
        suite: u8,
    ) -> Self {
        let spend_arr = ed25519_spend_pubkey
            .as_slice()
            .try_into()
            .expect("Invalid Ed25519 public key length");
        let disc_arr: [u8; 32] = x25519_discovery_pubkey
            .as_slice()
            .try_into()
            .expect("Invalid X25519 public key length");

        let spend_pubkey = Ed25519PublicKey::from_bytes(spend_arr).unwrap();
        let disc_pubkey = X25519PublicKey::from(disc_arr);

        let network_enum = match network.to_lowercase().as_str() {
            "mainnet" => RustSupportedNetwork::Mainnet,
            "testnet" => RustSupportedNetwork::Testnet,
            "netanet" => RustSupportedNetwork::Betanet,
            "devnet" => RustSupportedNetwork::Devnet,
            "custom" => RustSupportedNetwork::Custom([0u8; 32]),
            _ => panic!("Unsupported network"),
        };

        let suite_enum = match suite {
            0 => RustSupportedHpkeSuite::Base25519Sha512ChaCha20Poly1305,
            _ => panic!("Unsupported HPKE suite"),
        };

        Self {
            rust: RustMithrasAddr::from_keys(
                &spend_pubkey,
                &disc_pubkey,
                version,
                network_enum,
                suite_enum,
            ),
        }
    }
}
