use anyhow::{Result, anyhow};
use bech32::Hrp;
use ed25519_dalek::VerifyingKey as Ed25519PublicKey;
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey as X25519PublicKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MithrasAddr {
    pub version: u8,
    pub network: u8,
    pub suite: u8,
    pub spend_ed25519: Ed25519PublicKey,
    pub disc_x25519: X25519PublicKey,
}

impl MithrasAddr {
    pub fn encode(&self) -> String {
        let mut data = Vec::<u8>::with_capacity(3 + 32 + 32);
        data.push(self.version);
        data.push(self.network);
        data.push(self.suite);
        data.extend_from_slice(&self.spend_ed25519.to_bytes());
        data.extend_from_slice(&self.disc_x25519.to_bytes());
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
        let disc_arr: [u8; 32] = data[35..67].try_into()?;
        let disc = X25519PublicKey::from(disc_arr);

        Ok(Self {
            version,
            network,
            suite,
            spend_ed25519: spend,
            disc_x25519: disc,
        })
    }

    pub fn from_keys(
        spend: &Ed25519PublicKey,
        disc: &X25519PublicKey,
        version: u8,
        network: u8,
        suite: u8,
    ) -> Self {
        Self {
            version,
            network,
            suite,
            spend_ed25519: *spend,
            disc_x25519: *disc,
        }
    }
}
