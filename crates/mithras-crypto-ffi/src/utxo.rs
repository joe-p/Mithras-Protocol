use std::sync::Arc;

use mithras_crypto::{keypairs::DiscoveryKeypair, utxo::UtxoSecrets as RustUtxoSecrets};

use crate::{
    MithrasCryptoError,
    address::MithrasAddr,
    hpke::{HpkeEnvelope, TransactionMetadata},
};

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
        discovery_privkey: Vec<u8>,
        txn_metadata: TransactionMetadata,
    ) -> Result<Self, MithrasCryptoError> {
        let discovery_arr: [u8; 32] = discovery_pubkey.as_slice().try_into().map_err(|_| {
            MithrasCryptoError::Error("discovery_pubkey should be 32 bytes".to_string())
        })?;

        let discovery_priv_arr: [u8; 32] =
            discovery_privkey.as_slice().try_into().map_err(|_| {
                MithrasCryptoError::Error("discovery_privley should be 32 bytes".to_string())
            })?;

        let discovery_keypair = DiscoveryKeypair::from_keypair(discovery_priv_arr, discovery_arr);
        let rust_hpke_envelope: mithras_crypto::hpke::HpkeEnvelope =
            (<mithras_crypto::hpke::HpkeEnvelope as TryFrom<HpkeEnvelope>>::try_from(
                hpke_envelope,
            ))
            .map_err(|e| MithrasCryptoError::Error(e.to_string()))?;

        let rust_utxo_secrets = RustUtxoSecrets::from_hpke_envelope(
            rust_hpke_envelope,
            discovery_keypair,
            &(<mithras_crypto::hpke::TransactionMetadata as TryFrom<TransactionMetadata>>::try_from(txn_metadata)
                .map_err(|e| MithrasCryptoError::Error(e.to_string()))?),
        )
        .map_err(|e| MithrasCryptoError::Error(e.to_string()))?;

        Ok(UtxoSecrets {
            rust: rust_utxo_secrets,
        })
    }

    pub fn spending_secret(&self) -> Vec<u8> {
        self.rust.spending_secret.to_vec()
    }

    pub fn nullifier_secret(&self) -> Vec<u8> {
        self.rust.nullifier_secret.to_vec()
    }
}

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
        let rust_txn_metadata: mithras_crypto::hpke::TransactionMetadata =
            (<mithras_crypto::hpke::TransactionMetadata as TryFrom<
                crate::hpke::TransactionMetadata,
            >>::try_from(txn_metadata))
            .map_err(|e| MithrasCryptoError::Error(e.to_string()))?;
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
