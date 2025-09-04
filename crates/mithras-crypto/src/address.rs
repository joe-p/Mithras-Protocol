use anyhow::{Result, anyhow};
use bech32::Hrp;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey as X25519PublicKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MithrasAddr {
    pub version: u8,
    pub network: u8,
    pub suite: u8,
    pub spend_ed25519: [u8; 32],
    pub disc_x25519: [u8; 32],
}

impl MithrasAddr {
    pub fn encode(&self) -> String {
        let mut data = Vec::<u8>::with_capacity(3 + 32 + 32);
        data.push(self.version);
        data.push(self.network);
        data.push(self.suite);
        data.extend_from_slice(&self.spend_ed25519);
        data.extend_from_slice(&self.disc_x25519);
        bech32::encode::<bech32::Bech32m>(Hrp::parse_unchecked("mith"), &data).unwrap()
    }

    pub fn decode(s: &str) -> Result<Self> {
        let (hrp, data) = bech32::decode(s)?;
        if hrp.as_str() != "mith" {
            return Err(anyhow!(
                "invalid human-readable prefix. Got {}, expected mith",
                hrp
            ));
        }
        let version = data[0];
        let network = data[1];
        let suite = data[2];
        let spend = data[3..35].try_into()?;
        let disc = data[35..67].try_into()?;
        Ok(Self {
            version,
            network,
            suite,
            spend_ed25519: spend,
            disc_x25519: disc,
        })
    }

    pub fn from_keys(
        spend: &VerifyingKey,
        disc: &X25519PublicKey,
        version: u8,
        network: u8,
        suite: u8,
    ) -> Self {
        let spend_bytes = spend.to_bytes();
        let disc_bytes = disc.as_bytes();
        Self {
            version,
            network,
            suite,
            spend_ed25519: spend_bytes,
            disc_x25519: *disc_bytes,
        }
    }
}
