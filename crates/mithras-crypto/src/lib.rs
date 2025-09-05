pub mod address;
pub mod keypairs;

use curve25519_dalek::Scalar;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hpke_rs::Hpke;
use hpke_rs_libcrux::HpkeLibcrux;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

pub fn suite() -> Hpke<HpkeLibcrux> {
    Hpke::new(
        hpke_rs::Mode::Base,
        hpke_rs::hpke_types::KemAlgorithm::DhKem25519,
        hpke_rs::hpke_types::KdfAlgorithm::HkdfSha512,
        hpke_rs::hpke_types::AeadAlgorithm::ChaCha20Poly1305,
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HpkeEnvelope {
    /// The mithras version which determines the shape of the data in the plaintext
    pub version: u8,
    /// The HPKE suite identifier
    pub suite: u8,
    pub encapsulated_key_b64: String,
    pub ciphertext_b64: String,
}

const SECRET_SIZE: usize = 104;

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

pub fn compute_discovery_secret_sender(
    ephemeral_private: &X25519SecretKey,
    discovery_public: &X25519PublicKey,
) -> [u8; 32] {
    let shared_secret = ephemeral_private.diffie_hellman(discovery_public);
    *shared_secret.as_bytes()
}

pub fn compute_discovery_secret_receiver(
    discovery_private: &X25519SecretKey,
    ephemeral_public: &X25519PublicKey,
) -> [u8; 32] {
    let shared_secret = discovery_private.diffie_hellman(ephemeral_public);
    *shared_secret.as_bytes()
}

pub fn compute_discovery_tag(
    discovery_secret: &[u8; 32],
    sender: &[u8],
    fv: u64,
    lv: u64,
    lease: u64,
) -> Vec<u8> {
    let salt = [0u8; 0];
    let hk = Hkdf::<Sha256>::new(Some(&salt), discovery_secret);

    let mut tag_key = [0u8; 32];
    hk.expand(b"discovery-tag", &mut tag_key).unwrap();

    let mut hmac = Hmac::<Sha256>::new_from_slice(&tag_key).unwrap();
    hmac.update(sender);
    hmac.update(&fv.to_le_bytes());
    hmac.update(&lv.to_le_bytes());
    hmac.update(&lease.to_le_bytes());

    hmac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use crate::{
        address::MithrasAddr,
        keypairs::{
            DiscoveryKeypair, SpendKeypair, TweakedPrivate, derive_tweak_scalar,
            derive_tweaked_pubkey,
        },
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as B64};
    use ed25519_dalek::Verifier;

    use super::*;

    #[test]
    fn test_keypair_generation() {
        let spend_keypair = SpendKeypair::generate();
        let discovery_keypair = DiscoveryKeypair::generate();

        assert_eq!(spend_keypair.seed.len(), 32);
        assert_eq!(discovery_keypair.public_key.as_bytes().len(), 32);
    }

    #[test]
    fn test_discovery_secret_computation() {
        let discovery_keypair = DiscoveryKeypair::generate();
        let ephemeral_keypair = DiscoveryKeypair::generate();

        let discovery_secret_sender = compute_discovery_secret_sender(
            &ephemeral_keypair.private_key,
            &discovery_keypair.public_key,
        );

        let discovery_secret_receiver = compute_discovery_secret_receiver(
            &discovery_keypair.private_key,
            &ephemeral_keypair.public_key,
        );

        assert_eq!(discovery_secret_sender, discovery_secret_receiver);
    }

    #[test]
    fn test_tweaked_keypair_computation() {
        let spend_keypair = SpendKeypair::generate();
        let discovery_keypair = DiscoveryKeypair::generate();
        let ephemeral_keypair = DiscoveryKeypair::generate();

        let discovery_secret_sender = compute_discovery_secret_sender(
            &ephemeral_keypair.private_key,
            &discovery_keypair.public_key,
        );

        let tweak_scalar = derive_tweak_scalar(&discovery_secret_sender);

        let tweaked_keypair_sender =
            derive_tweaked_pubkey(&spend_keypair.public_key, &tweak_scalar);

        let tweaked_keypair_receiver = TweakedPrivate::derive(&spend_keypair, &tweak_scalar);

        assert_eq!(
            tweaked_keypair_sender.to_bytes(),
            tweaked_keypair_receiver.public_key().to_bytes()
        );
    }

    #[test]
    fn test_discovery_tag() {
        let discovery_keypair = DiscoveryKeypair::generate();
        let ephemeral_keypair = DiscoveryKeypair::generate();

        let discovery_secret_sender = compute_discovery_secret_sender(
            &ephemeral_keypair.private_key,
            &discovery_keypair.public_key,
        );

        let discovery_secret_receiver = compute_discovery_secret_receiver(
            &discovery_keypair.private_key,
            &ephemeral_keypair.public_key,
        );

        let sender_data = b"sender_identifier";
        let discovery_tag_sender =
            compute_discovery_tag(&discovery_secret_sender, sender_data, 1000, 2000, 3600);

        let discovery_tag_receiver =
            compute_discovery_tag(&discovery_secret_receiver, sender_data, 1000, 2000, 3600);

        assert_eq!(discovery_tag_sender, discovery_tag_receiver);
    }

    #[test]
    fn test_ed25519_signing_with_tweaked_key() {
        let spend_keypair = SpendKeypair::generate();
        let discovery_secret = [42u8; 32];
        let tweak_scalar = derive_tweak_scalar(&discovery_secret);
        let tweaked_keypair_receiver =
            derive_tweaked_pubkey(&spend_keypair.public_key, &tweak_scalar);

        let msg = b"example spend authorization";
        let tweaked_priv = TweakedPrivate::derive(&spend_keypair, &tweak_scalar);
        let sig = tweaked_priv.sign(msg);

        let verify_res = tweaked_keypair_receiver.verify_strict(msg, &sig);
        if verify_res.is_err() {
            tweaked_keypair_receiver.verify(msg, &sig).unwrap();
        }
    }

    #[test]
    fn test_hpke_encryption_decryption() -> anyhow::Result<()> {
        let mut hpke = suite();
        let hpke_recipient = hpke.generate_key_pair().unwrap();

        let info = b"mithras|network:mainnet|app:1337|v:1"; // used by KDF
        let aad = b"txid:BLAH...BLAH";

        let (encapsulated_key, mut sender_ctx) = hpke
            .setup_sender(hpke_recipient.public_key(), info, None, None, None)
            .unwrap();

        let mithras_secret = UtxoSecrets {
            spending_secret: [42u8; 32],
            nullifier_secret: [43u8; 32],
            amount: 1000,
            tweak_scalar: Scalar::from(7u64),
        };
        let secret_bytes: [u8; SECRET_SIZE] = mithras_secret.into();
        let ct = sender_ctx.seal(aad, &secret_bytes).unwrap();

        let env = HpkeEnvelope {
            version: 1,
            suite: 1,
            encapsulated_key_b64: B64.encode(&encapsulated_key),
            ciphertext_b64: B64.encode(&ct),
        };

        let json = serde_json::to_string(&env)?;
        let env2: HpkeEnvelope = serde_json::from_str(&json)?;
        let enclosed_key_bytes = B64.decode(&env2.encapsulated_key_b64)?;
        let ct_bytes = B64.decode(&env2.ciphertext_b64)?;

        let mut recv_ctx = hpke
            .setup_receiver(
                enclosed_key_bytes.as_slice(),
                hpke_recipient.private_key(),
                info,
                None,
                None,
                None,
            )
            .unwrap();

        let pt = recv_ctx.open(aad, ct_bytes.as_slice()).unwrap();

        assert_eq!(&pt, &secret_bytes);
        Ok(())
    }

    #[test]
    fn test_mithras_address_encoding_decoding() -> anyhow::Result<()> {
        let spend_keypair = SpendKeypair::generate();
        let discovery_keypair = DiscoveryKeypair::generate();
        let discovery_secret = [42u8; 32];
        let tweak_scalar = derive_tweak_scalar(&discovery_secret);
        let tweaked_keypair_receiver = TweakedPrivate::derive(&spend_keypair, &tweak_scalar);

        let mithras_addr = MithrasAddr::from_keys(
            tweaked_keypair_receiver.public_key(),
            &discovery_keypair.public_key,
            1, // version
            0, // network
            1, // suite
        );

        let encoded_addr = mithras_addr.encode();
        let decoded_addr = MithrasAddr::decode(&encoded_addr)?;

        assert_eq!(decoded_addr.version, mithras_addr.version);
        assert_eq!(decoded_addr.network, mithras_addr.network);
        assert_eq!(decoded_addr.suite, mithras_addr.suite);
        assert_eq!(decoded_addr.spend_ed25519, mithras_addr.spend_ed25519);
        assert_eq!(decoded_addr.disc_x25519, mithras_addr.disc_x25519);

        Ok(())
    }

    #[test]
    fn test_complete_mithras_protocol_flow() -> anyhow::Result<()> {
        let spend_keypair = SpendKeypair::generate();
        let discovery_keypair = DiscoveryKeypair::generate();
        let ephemeral_keypair = DiscoveryKeypair::generate();

        let discovery_secret_sender = compute_discovery_secret_sender(
            &ephemeral_keypair.private_key,
            &discovery_keypair.public_key,
        );

        let tweak_scalar = derive_tweak_scalar(&discovery_secret_sender);

        let tweaked_keypair_sender =
            derive_tweaked_pubkey(&spend_keypair.public_key, &tweak_scalar);

        let sender_data = b"sender_identifier";
        let discovery_tag =
            compute_discovery_tag(&discovery_secret_sender, sender_data, 1000, 2000, 3600);

        let discovery_secret_receiver = compute_discovery_secret_receiver(
            &discovery_keypair.private_key,
            &ephemeral_keypair.public_key,
        );

        assert_eq!(discovery_secret_sender, discovery_secret_receiver);

        let tweak_scalar_receiver = derive_tweak_scalar(&discovery_secret_receiver);
        assert_eq!(tweak_scalar, tweak_scalar_receiver);

        let tweaked_keypair_receiver = TweakedPrivate::derive(&spend_keypair, &tweak_scalar);

        assert_eq!(
            tweaked_keypair_sender.to_bytes(),
            tweaked_keypair_receiver.public_key().to_bytes()
        );

        let discovery_tag_receiver =
            compute_discovery_tag(&discovery_secret_receiver, sender_data, 1000, 2000, 3600);
        assert_eq!(discovery_tag, discovery_tag_receiver);

        let msg = b"example spend authorization";
        let tweaked_priv = TweakedPrivate::derive(&spend_keypair, &tweak_scalar);
        let sig = tweaked_priv.sign(msg);

        let verify_res = tweaked_keypair_receiver
            .public_key()
            .verify_strict(msg, &sig);
        if verify_res.is_err() {
            tweaked_keypair_receiver
                .public_key()
                .verify(msg, &sig)
                .unwrap();
        }

        let mut hpke = suite();
        let hpke_recipient = hpke.generate_key_pair().unwrap();

        let info = b"mithras|network:mainnet|app:1337|v:1";
        let aad = b"txid:BLAH...BLAH";

        let (encapsulated_key, mut sender_ctx) = hpke
            .setup_sender(hpke_recipient.public_key(), info, None, None, None)
            .unwrap();

        let mithras_secret = UtxoSecrets {
            spending_secret: [42u8; 32],
            nullifier_secret: [43u8; 32],
            amount: 1000,
            tweak_scalar,
        };
        let secret_bytes: [u8; SECRET_SIZE] = mithras_secret.into();
        let ct = sender_ctx.seal(aad, &secret_bytes).unwrap();

        let env = HpkeEnvelope {
            version: 1,
            suite: 1,
            encapsulated_key_b64: B64.encode(&encapsulated_key),
            ciphertext_b64: B64.encode(&ct),
        };

        let json = serde_json::to_string(&env)?;
        let env2: HpkeEnvelope = serde_json::from_str(&json)?;
        let enclosed_key_bytes = B64.decode(&env2.encapsulated_key_b64)?;
        let ct_bytes = B64.decode(&env2.ciphertext_b64)?;

        let mut recv_ctx = hpke
            .setup_receiver(
                enclosed_key_bytes.as_slice(),
                hpke_recipient.private_key(),
                info,
                None,
                None,
                None,
            )
            .unwrap();

        let pt = recv_ctx.open(aad, ct_bytes.as_slice()).unwrap();

        assert_eq!(&pt, &secret_bytes);

        let mithras_addr = MithrasAddr::from_keys(
            tweaked_keypair_receiver.public_key(),
            &discovery_keypair.public_key,
            1,
            0,
            1,
        );

        let encoded_addr = mithras_addr.encode();
        let decoded_addr = MithrasAddr::decode(&encoded_addr)?;
        assert_eq!(decoded_addr.version, mithras_addr.version);
        assert_eq!(decoded_addr.network, mithras_addr.network);
        assert_eq!(decoded_addr.suite, mithras_addr.suite);
        assert_eq!(decoded_addr.spend_ed25519, mithras_addr.spend_ed25519);
        assert_eq!(decoded_addr.disc_x25519, mithras_addr.disc_x25519);

        Ok(())
    }
}
