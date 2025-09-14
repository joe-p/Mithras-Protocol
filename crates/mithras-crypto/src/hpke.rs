use std::fmt::Display;

use ed25519_dalek::VerifyingKey as Ed25519PublicKey;
use hpke_rs::Hpke;
use hpke_rs_libcrux::HpkeLibcrux;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const CIPHER_TEXT_SIZE: usize = crate::utxo::SECRET_SIZE + 16;

fn serialize_ciphertext<S>(data: &[u8; CIPHER_TEXT_SIZE], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    data.serialize(serializer)
}

fn deserialize_ciphertext<'de, D>(deserializer: D) -> Result<[u8; CIPHER_TEXT_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    let vec: Vec<u8> = Vec::deserialize(deserializer)?;
    vec.try_into()
        .map_err(|_| serde::de::Error::custom("wrong length"))
}

pub enum SupportedNetwork {
    Mainnet,
    Testnet,
    Betanet,
    Devnet,
    Custom([u8; 32]),
}

impl Display for SupportedNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SupportedNetwork::Mainnet => write!(f, "mainnet"),
            SupportedNetwork::Testnet => write!(f, "testnet"),
            SupportedNetwork::Betanet => write!(f, "betanet"),
            SupportedNetwork::Devnet => write!(f, "devnet"),
            SupportedNetwork::Custom(tag) => write!(f, "{:x?}", tag),
        }
    }
}

pub struct TransactionMetadata {
    pub sender: Ed25519PublicKey,
    pub first_valid: u64,
    pub last_valid: u64,
    pub lease: [u8; 32],
    pub network: SupportedNetwork,
    pub app_id: u64,
}

// TODO: better serialization
impl TransactionMetadata {
    pub fn info(&self) -> Vec<u8> {
        format!("mithras|network:{}|app:{}|v:1", self.network, self.app_id)
            .as_bytes()
            .to_vec()
    }

    pub fn aad(&self) -> Vec<u8> {
        format!(
            "txid:{:x?}|fv:{}|lv:{}|lease:{:x?}",
            self.sender, self.first_valid, self.last_valid, self.lease
        )
        .as_bytes()
        .to_vec()
    }
}

/// Supported HPKE suites in Mithras. Currently, only one suite is supported which uses X25519,
/// this not PQ-secure. In the future, PQ suites may be supported. See the tracking issue here:
/// https://github.com/joe-p/Mithras-Protocol/issues/21
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SupportedHpkeSuite {
    Base25519Sha512ChaCha20Poly1305 = 0x00,
}

impl SupportedHpkeSuite {
    pub fn suite(&self) -> Hpke<HpkeLibcrux> {
        match self {
            SupportedHpkeSuite::Base25519Sha512ChaCha20Poly1305 => Hpke::new(
                hpke_rs::Mode::Base,
                hpke_rs::hpke_types::KemAlgorithm::DhKem25519,
                hpke_rs::hpke_types::KdfAlgorithm::HkdfSha512,
                hpke_rs::hpke_types::AeadAlgorithm::ChaCha20Poly1305,
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HpkeEnvelope {
    /// The mithras version which determines the shape of the data in the plaintext
    pub version: u8,
    /// The HPKE suite identifier
    pub suite: SupportedHpkeSuite,
    pub encapsulated_key: [u8; 32],
    #[serde(
        serialize_with = "serialize_ciphertext",
        deserialize_with = "deserialize_ciphertext"
    )]
    pub ciphertext: [u8; CIPHER_TEXT_SIZE],
    pub discoery_tag: [u8; 32],
}
