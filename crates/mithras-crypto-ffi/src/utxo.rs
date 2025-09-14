use std::sync::Arc;

use mithras_crypto::{keypairs::DiscoveryKeypair, utxo::UtxoSecrets as RustUtxoSecrets};

use crate::{
    MithrasCryptoError,
    address::MithrasAddr,
    hpke::{HpkeEnvelope, TransactionMetadata},
};

// #[derive(Clone, Debug, PartialEq)]
// pub struct UtxoSecrets {
//     pub spending_secret: [u8; 32],
//     pub nullifier_secret: [u8; 32],
//     pub amount: u64,
//     pub tweak_scalar: Scalar,
//     pub tweaked_pubkey: Ed25519PublicKey,
// }

#[derive(uniffi::Object)]
pub struct UtxoSecrets {
    rust: RustUtxoSecrets,
}

#[uniffi::export]
impl UtxoSecrets {
    #[uniffi::constructor]
    pub fn from_hpke_envelope(
        hpke_envelope: HpkeEnvelope,
        discovery_pubkey: Vec<u8>,
        discoery_privley: Vec<u8>,
        txn_metadata: TransactionMetadata,
    ) -> Self {
        let discovery_arr: [u8; 32] = discovery_pubkey
            .as_slice()
            .try_into()
            .expect("discovery_pubkey should be 32 bytes");

        let discovery_priv_arr: [u8; 32] = discoery_privley
            .as_slice()
            .try_into()
            .expect("discovery_privley should be 32 bytes");

        let discovery_keypair = DiscoveryKeypair::from_keypair(discovery_priv_arr, discovery_arr);
        let rust_hpke_envelope: mithras_crypto::hpke::HpkeEnvelope = hpke_envelope.into();

        let rust_utxo_secrets = RustUtxoSecrets::from_hpke_envelope(
            rust_hpke_envelope,
            discovery_keypair,
            &txn_metadata.into(),
        );

        UtxoSecrets {
            rust: rust_utxo_secrets,
        }
    }

    pub fn spending_secret(&self) -> Vec<u8> {
        self.rust.spending_secret.to_vec()
    }

    pub fn nullifier_secret(&self) -> Vec<u8> {
        self.rust.nullifier_secret.to_vec()
    }
}

// #[derive(Debug, PartialEq)]
// pub struct UtxoInputs {
//     pub secrets: UtxoSecrets,
//     pub hpke_envelope: HpkeEnvelope,
// }

#[derive(uniffi::Object)]
pub struct UtxoInputs {
    rust: mithras_crypto::utxo::UtxoInputs,
}

#[uniffi::export]
impl UtxoInputs {
    #[uniffi::constructor]
    pub fn generate(
        txn_metadata: TransactionMetadata,
        amount: u64,
        receiver: Arc<MithrasAddr>,
    ) -> Result<Self, MithrasCryptoError> {
        let rust_txn_metadata: mithras_crypto::hpke::TransactionMetadata = txn_metadata.into();
        let rust_receiver: mithras_crypto::address::MithrasAddr = receiver.rust.clone();
        let rust_utxo_inputs =
            mithras_crypto::utxo::UtxoInputs::generate(&rust_txn_metadata, amount, &rust_receiver)
                .map_err(|e| MithrasCryptoError::Error(e.to_string()))?;
        Ok(UtxoInputs {
            rust: rust_utxo_inputs,
        })
    }

    pub fn envelope(&self) -> HpkeEnvelope {
        HpkeEnvelope::from(self.rust.hpke_envelope.clone())
    }

    pub fn secrets(&self) -> UtxoSecrets {
        UtxoSecrets {
            rust: self.rust.secrets.clone(),
        }
    }
}
