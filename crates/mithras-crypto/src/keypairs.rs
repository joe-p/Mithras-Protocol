use curve25519_dalek::scalar::clamp_integer;
use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_TABLE};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Clone)]
pub struct DiscoveryKeypair {
    pub private_key: StaticSecret,
    pub public_key: X25519PublicKey,
}

impl DiscoveryKeypair {
    pub fn generate() -> Self {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = X25519PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpendKeypair {
    pub seed: [u8; 32],
    pub public_key: VerifyingKey,
}

impl SpendKeypair {
    pub fn generate() -> Self {
        use rand::RngCore as _;
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let public_key = sk.verifying_key();

        Self { seed, public_key }
    }

    pub fn a_scalar(&self) -> Scalar {
        let digest = Sha512::digest(self.seed);
        let mut a_bytes = [0u8; 32];
        a_bytes.copy_from_slice(&digest[..32]);
        Scalar::from_bytes_mod_order(clamp_integer(a_bytes))
    }

    pub fn prefix(&self) -> [u8; 32] {
        let digest = Sha512::digest(self.seed);
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&digest[32..64]);
        prefix
    }
}

#[derive(Debug, Clone)]
pub struct TweakedPrivate {
    pub a_scalar: Scalar,
    pub prefix: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct TweakedKeypair {
    pub private: Option<TweakedPrivate>,
    pub public_key: VerifyingKey,
}
