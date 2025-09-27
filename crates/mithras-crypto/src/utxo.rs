use curve25519_dalek::Scalar;

pub const SECRET_SIZE: usize = 136;
use ed25519_dalek::VerifyingKey as Ed25519PublicKey;
use hpke_rs::HpkePublicKey;

use crate::{
    MithrasError,
    address::MithrasAddr,
    discovery::{compute_discovery_secret_sender, compute_discovery_tag},
    hpke::{HpkeEnvelope, SupportedHpkeSuite},
    keypairs::{DiscoveryKeypair, derive_tweak_scalar, derive_tweaked_pubkey},
};

#[derive(Clone, Debug, PartialEq)]
pub struct UtxoSecrets {
    pub spending_secret: [u8; 32],
    pub nullifier_secret: [u8; 32],
    pub amount: u64,
    pub tweak_scalar: Scalar,
    pub tweaked_pubkey: Ed25519PublicKey,
}

impl UtxoSecrets {
    pub fn from_hpke_envelope(
        hpke_envelope: HpkeEnvelope,
        discovery_keypair: DiscoveryKeypair,
        txn_metadata: &crate::hpke::TransactionMetadata,
    ) -> Result<Self, MithrasError> {
        let hpke = SupportedHpkeSuite::Base25519Sha512ChaCha20Poly1305.suite();

        let hpke_recipient_private =
            hpke_rs::HpkePrivateKey::new(discovery_keypair.private_key().to_bytes().to_vec());

        let mut recv_ctx = hpke
            .setup_receiver(
                &hpke_envelope.encapsulated_key,
                &hpke_recipient_private,
                &txn_metadata.info(),
                None,
                None,
                None,
            )
            .map_err(|e| MithrasError::HpkeOperation { msg: e.to_string() })?;

        let pt = recv_ctx
            .open(&txn_metadata.aad(), &hpke_envelope.ciphertext)
            .map_err(|e| MithrasError::HpkeOperation { msg: e.to_string() })?;
        let pt_array: [u8; SECRET_SIZE] =
            pt.try_into().map_err(|_| MithrasError::DataConversion {
                msg: "Invalid plaintext size for UTXO secrets".to_string(),
            })?;
        UtxoSecrets::try_from(pt_array)
    }
}

impl TryFrom<[u8; SECRET_SIZE]> for UtxoSecrets {
    type Error = MithrasError;

    fn try_from(bytes: [u8; SECRET_SIZE]) -> Result<Self, Self::Error> {
        let mut spending_secret = [0u8; 32];
        let mut nullifier_secret = [0u8; 32];

        spending_secret.copy_from_slice(&bytes[0..32]);
        nullifier_secret.copy_from_slice(&bytes[32..64]);
        let amount = u64::from_be_bytes(bytes[64..72].try_into().map_err(|_| {
            MithrasError::DataConversion {
                msg: "Failed to convert amount bytes".to_string(),
            }
        })?);
        let tweak_scalar =
            Scalar::from_bytes_mod_order(bytes[72..104].try_into().map_err(|_| {
                MithrasError::DataConversion {
                    msg: "Failed to convert tweak scalar bytes".to_string(),
                }
            })?);
        let tweak_pubkey =
            Ed25519PublicKey::from_bytes(&bytes[104..136].try_into().map_err(|_| {
                MithrasError::DataConversion {
                    msg: "Failed to convert tweaked pubkey bytes".to_string(),
                }
            })?)
            .map_err(|e| MithrasError::Ed25519KeyParsing { msg: e.to_string() })?;

        Ok(Self {
            spending_secret,
            nullifier_secret,
            amount,
            tweak_scalar,
            tweaked_pubkey: tweak_pubkey,
        })
    }
}

impl From<UtxoSecrets> for [u8; SECRET_SIZE] {
    fn from(secret: UtxoSecrets) -> Self {
        let mut bytes = [0u8; SECRET_SIZE];
        bytes[0..32].copy_from_slice(&secret.spending_secret);
        bytes[32..64].copy_from_slice(&secret.nullifier_secret);
        bytes[64..72].copy_from_slice(&secret.amount.to_be_bytes());
        bytes[72..104].copy_from_slice(&secret.tweak_scalar.to_bytes());
        bytes[104..136].copy_from_slice(&secret.tweaked_pubkey.to_bytes());
        bytes
    }
}

#[derive(Debug, PartialEq)]
pub struct UtxoInputs {
    pub secrets: UtxoSecrets,
    pub hpke_envelope: HpkeEnvelope,
}

impl UtxoInputs {
    pub fn generate(
        txn_metadata: &crate::hpke::TransactionMetadata,
        amount: u64,
        receiver: &MithrasAddr,
    ) -> Result<Self, MithrasError> {
        let mut hpke = SupportedHpkeSuite::Base25519Sha512ChaCha20Poly1305.suite();

        let ephemeral_keypair = DiscoveryKeypair::generate()?;

        let discovery_secret =
            compute_discovery_secret_sender(ephemeral_keypair.private_key(), &receiver.disc_x25519);

        let tweak_scalar = derive_tweak_scalar(&discovery_secret);

        let tweaked_pubkey = derive_tweaked_pubkey(&receiver.spend_ed25519, &tweak_scalar)?;

        let discovery_tag = compute_discovery_tag(
            &discovery_secret,
            &txn_metadata.sender,
            txn_metadata.first_valid,
            txn_metadata.last_valid,
            txn_metadata.lease,
        )?;

        // TODO: ensure secrets are in scalar field
        let mut spending_secret = [0u8; 32];
        getrandom::fill(&mut spending_secret)
            .map_err(|e| MithrasError::RandomGeneration { msg: e.to_string() })?;

        let mut nullifier_secret = [0u8; 32];
        getrandom::fill(&mut nullifier_secret)
            .map_err(|e| MithrasError::RandomGeneration { msg: e.to_string() })?;

        let (encapsulated_key, mut sender_ctx) = hpke
            .setup_sender(
                &HpkePublicKey::new(receiver.disc_x25519.to_bytes().to_vec()),
                &txn_metadata.info(),
                None,
                None,
                None,
            )
            .map_err(|e| MithrasError::HpkeOperation { msg: e.to_string() })?;

        let mithras_secret = UtxoSecrets {
            spending_secret,
            nullifier_secret,
            amount,
            tweak_scalar,
            tweaked_pubkey,
        };

        let secret_bytes: [u8; SECRET_SIZE] = mithras_secret.clone().into();
        let ct = sender_ctx
            .seal(&txn_metadata.aad(), &secret_bytes)
            .map_err(|e| MithrasError::HpkeOperation { msg: e.to_string() })?;

        let hpke_envelope = HpkeEnvelope {
            version: 1,
            suite: SupportedHpkeSuite::Base25519Sha512ChaCha20Poly1305,
            encapsulated_key: encapsulated_key.try_into().map_err(|_| {
                MithrasError::DataConversion {
                    msg: "Invalid encapsulated key size".to_string(),
                }
            })?,
            ciphertext: ct.try_into().map_err(|_| MithrasError::DataConversion {
                msg: "Invalid ciphertext size".to_string(),
            })?,
            discovery_tag,
        };

        Ok(UtxoInputs {
            secrets: mithras_secret,
            hpke_envelope,
        })
    }
}
