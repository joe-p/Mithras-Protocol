use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

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
) -> [u8; 32] {
    let salt = [0u8; 0];
    let hk = Hkdf::<Sha256>::new(Some(&salt), discovery_secret);

    let mut tag_key = [0u8; 32];
    hk.expand(b"discovery-tag", &mut tag_key).unwrap();

    let mut hmac = Hmac::<Sha256>::new_from_slice(&tag_key).unwrap();
    hmac.update(sender);
    hmac.update(&fv.to_le_bytes());
    hmac.update(&lv.to_le_bytes());
    hmac.update(&lease.to_le_bytes());

    hmac.finalize().into_bytes().into()
}
