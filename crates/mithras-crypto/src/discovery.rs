use ed25519_dalek::VerifyingKey as Ed25519PublicKey;
use sha2::{Digest, Sha512_256};
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
    sender: &Ed25519PublicKey,
    fv: u64,
    lv: u64,
    lease: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha512_256::new();
    hasher.update(b"discovery-tag");
    hasher.update(discovery_secret);
    hasher.update(sender.to_bytes());
    hasher.update(fv.to_le_bytes());
    hasher.update(lv.to_le_bytes());
    hasher.update(lease);
    hasher.finalize().into()
}
