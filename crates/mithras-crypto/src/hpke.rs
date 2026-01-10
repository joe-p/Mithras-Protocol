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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SupportedNetwork {
    Mainnet,
    Testnet,
    Betanet,
    Devnet,
    Custom([u8; 32]),
}

impl From<SupportedNetwork> for u8 {
    fn from(network: SupportedNetwork) -> Self {
        match network {
            SupportedNetwork::Mainnet => 0x00,
            SupportedNetwork::Testnet => 0x01,
            SupportedNetwork::Betanet => 0x02,
            SupportedNetwork::Devnet => 0x03,
            SupportedNetwork::Custom(_) => 0xFF,
        }
    }
}

impl TryFrom<u8> for SupportedNetwork {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(SupportedNetwork::Mainnet),
            0x01 => Ok(SupportedNetwork::Testnet),
            0x02 => Ok(SupportedNetwork::Betanet),
            0x03 => Ok(SupportedNetwork::Devnet),
            0xFF => Ok(SupportedNetwork::Custom([0u8; 32])),
            _ => Err(anyhow::anyhow!("Invalid network identifier: {}", value)),
        }
    }
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

impl From<SupportedHpkeSuite> for u8 {
    fn from(suite: SupportedHpkeSuite) -> Self {
        match suite {
            SupportedHpkeSuite::Base25519Sha512ChaCha20Poly1305 => 0x00,
        }
    }
}

impl TryFrom<u8> for SupportedHpkeSuite {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(SupportedHpkeSuite::Base25519Sha512ChaCha20Poly1305),
            _ => Err(anyhow::anyhow!("Invalid HPKE suite identifier: {}", value)),
        }
    }
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
    /// HPKE KEM encapsulated key (sender's HPKE ephemeral public key)
    pub encapsulated_key: [u8; 32],
    #[serde(
        serialize_with = "serialize_ciphertext",
        deserialize_with = "deserialize_ciphertext"
    )]
    pub ciphertext: [u8; CIPHER_TEXT_SIZE],
    /// Discovery tag for fast output scanning
    pub discovery_tag: [u8; 32],
    /// X25519 ephemeral public key used solely for discovery tag derivation
    /// (may differ from `encapsulated_key` when HPKE KEM generates its own ephemeral).
    pub discovery_ephemeral: [u8; 32],
}

pub const HPKE_SIZE: usize = 1 + 1 + 32 + CIPHER_TEXT_SIZE + 32 + 32;

impl HpkeEnvelope {
    pub fn discovery_check(
        &self,
        discovery_private: &x25519_dalek::StaticSecret,
        txn_metadata: &TransactionMetadata,
    ) -> bool {
        let ephemeral_public = x25519_dalek::PublicKey::from(self.discovery_ephemeral);
        let discovery_secret = crate::discovery::compute_discovery_secret_receiver(
            discovery_private,
            &ephemeral_public,
        );

        let computed_tag = crate::discovery::compute_discovery_tag(
            &discovery_secret,
            &txn_metadata.sender,
            txn_metadata.first_valid,
            txn_metadata.last_valid,
            txn_metadata.lease,
        );

        computed_tag == self.discovery_tag
    }

    pub fn as_bytes(&self) -> [u8; HPKE_SIZE] {
        let mut encoded = [0u8; HPKE_SIZE];
        encoded[0] = self.version;
        encoded[1] = u8::from(self.suite);
        encoded[2..34].copy_from_slice(&self.encapsulated_key);
        encoded[34..(34 + CIPHER_TEXT_SIZE)].copy_from_slice(&self.ciphertext);
        encoded[(34 + CIPHER_TEXT_SIZE)..(34 + CIPHER_TEXT_SIZE + 32)]
            .copy_from_slice(&self.discovery_tag);
        encoded[(34 + CIPHER_TEXT_SIZE + 32)..].copy_from_slice(&self.discovery_ephemeral);
        encoded
    }

    pub fn from_bytes(data: &[u8; HPKE_SIZE]) -> Result<Self, anyhow::Error> {
        let version = data[0];
        let suite = SupportedHpkeSuite::try_from(data[1])?;
        let mut encapsulated_key = [0u8; 32];
        encapsulated_key.copy_from_slice(&data[2..34]);
        let mut ciphertext = [0u8; CIPHER_TEXT_SIZE];
        ciphertext.copy_from_slice(&data[34..(34 + CIPHER_TEXT_SIZE)]);
        let mut discovery_tag = [0u8; 32];
        discovery_tag.copy_from_slice(&data[(34 + CIPHER_TEXT_SIZE)..(34 + CIPHER_TEXT_SIZE + 32)]);
        let mut discovery_ephemeral = [0u8; 32];
        discovery_ephemeral.copy_from_slice(&data[(34 + CIPHER_TEXT_SIZE + 32)..]);

        Ok(HpkeEnvelope {
            version,
            suite,
            encapsulated_key,
            ciphertext,
            discovery_tag,
            discovery_ephemeral,
        })
    }
}
