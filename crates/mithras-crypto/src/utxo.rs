use curve25519_dalek::Scalar;

pub const SECRET_SIZE: usize = 104;
use ed25519_dalek::VerifyingKey as Ed25519PublicKey;
use getrandom::getrandom;
use hpke_rs::HpkePublicKey;

use crate::{
    address::MithrasAddr,
    discovery::{compute_discovery_secret_sender, compute_discovery_tag},
    hpke::{HpkeEnvelope, suite},
    keypairs::{DiscoveryKeypair, derive_tweak_scalar, derive_tweaked_pubkey},
};

#[derive(Clone, Debug)]
pub struct UtxoSecrets {
    pub spending_secret: [u8; 32],
    pub nullifier_secret: [u8; 32],
    pub amount: u64,
    pub tweak_scalar: Scalar,
}

impl From<[u8; SECRET_SIZE]> for UtxoSecrets {
    fn from(bytes: [u8; SECRET_SIZE]) -> Self {
        let mut spending_secret = [0u8; 32];
        let mut nullifier_secret = [0u8; 32];

        spending_secret.copy_from_slice(&bytes[0..32]);
        nullifier_secret.copy_from_slice(&bytes[32..64]);
        let amount = u64::from_be_bytes(bytes[64..72].try_into().unwrap());
        let tweak_scalar = Scalar::from_bytes_mod_order(bytes[72..104].try_into().unwrap());

        Self {
            spending_secret,
            nullifier_secret,
            amount,
            tweak_scalar,
        }
    }
}

impl From<UtxoSecrets> for [u8; SECRET_SIZE] {
    fn from(secret: UtxoSecrets) -> Self {
        let mut bytes = [0u8; SECRET_SIZE];
        bytes[0..32].copy_from_slice(&secret.spending_secret);
        bytes[32..64].copy_from_slice(&secret.nullifier_secret);
        bytes[64..72].copy_from_slice(&secret.amount.to_be_bytes());
        bytes[72..104].copy_from_slice(&secret.tweak_scalar.to_bytes());
        bytes
    }
}

pub struct UtxoInputs {
    pub secrets: UtxoSecrets,
    pub receiver: Ed25519PublicKey,
    pub hpke_envelope: HpkeEnvelope,
}

impl UtxoInputs {
    pub fn generate(
        sender: ed25519_dalek::VerifyingKey,
        amount: u64,
        receiver: MithrasAddr,
    ) -> Result<Self, String> {
        let mut hpke = suite();

        let ephemeral_keypair = DiscoveryKeypair::generate();

        let discovery_secret =
            compute_discovery_secret_sender(ephemeral_keypair.private_key(), &receiver.disc_x25519);

        let tweak_scalar = derive_tweak_scalar(&discovery_secret);

        let tweaked_pubkey = derive_tweaked_pubkey(&receiver.spend_ed25519, &tweak_scalar);

        let discovery_tag =
            compute_discovery_tag(&discovery_secret, &sender.to_bytes(), 1000, 2000, 3600);

        // TODO: ensure secrets are in scalar field
        let mut spending_secret = [0u8; 32];
        getrandom(&mut spending_secret).map_err(|e| e.to_string())?;

        let mut nullifier_secret = [0u8; 32];
        getrandom(&mut nullifier_secret).map_err(|e| e.to_string())?;

        // TODO: proper info and aad
        let info = b"mithras|network:testnet|app:1337|v:1"; // used by KDF
        let aad = b"txid:BLAH...BLAH";

        let (encapsulated_key, mut sender_ctx) = hpke
            .setup_sender(
                &HpkePublicKey::new(receiver.disc_x25519.to_bytes().to_vec()),
                info,
                None,
                None,
                None,
            )
            .unwrap();

        let mithras_secret = UtxoSecrets {
            spending_secret,
            nullifier_secret,
            amount,
            tweak_scalar,
        };
        let secret_bytes: [u8; SECRET_SIZE] = mithras_secret.clone().into();
        let ct = sender_ctx.seal(aad, &secret_bytes).unwrap();

        let hpke_envelope = HpkeEnvelope {
            version: 1,
            suite: 1,
            encapsulated_key: encapsulated_key.try_into().unwrap(),
            ciphertext: ct.try_into().unwrap(),
            discoery_tag: discovery_tag,
        };

        Ok(UtxoInputs {
            secrets: mithras_secret,
            receiver: tweaked_pubkey,
            hpke_envelope,
        })
    }
}
