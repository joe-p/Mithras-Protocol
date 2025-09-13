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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeEnvelope {
    /// The mithras version which determines the shape of the data in the plaintext
    pub version: u8,
    /// The HPKE suite identifier
    pub suite: u8,
    pub encapsulated_key: [u8; 32],
    #[serde(
        serialize_with = "serialize_ciphertext",
        deserialize_with = "deserialize_ciphertext"
    )]
    pub ciphertext: [u8; CIPHER_TEXT_SIZE],
}

pub fn suite() -> Hpke<HpkeLibcrux> {
    Hpke::new(
        hpke_rs::Mode::Base,
        hpke_rs::hpke_types::KemAlgorithm::DhKem25519,
        hpke_rs::hpke_types::KdfAlgorithm::HkdfSha512,
        hpke_rs::hpke_types::AeadAlgorithm::ChaCha20Poly1305,
    )
}
