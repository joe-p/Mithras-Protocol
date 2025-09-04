use curve25519_dalek::scalar::clamp_integer;
use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_TABLE};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha512};
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

impl TweakedPrivate {
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let a_g = (ED25519_BASEPOINT_TABLE * &self.a_scalar)
            .compress()
            .to_bytes();
        let public_locked =
            VerifyingKey::from_bytes(&a_g).expect("derived verifying key must be valid");

        let esk = ed25519_dalek::hazmat::ExpandedSecretKey {
            scalar: self.a_scalar,
            hash_prefix: self.prefix,
        };
        ed25519_dalek::hazmat::raw_sign::<Sha512>(&esk, msg, &public_locked)
    }
}

#[derive(Debug, Clone)]
pub struct TweakedKeypair {
    pub private: Option<TweakedPrivate>,
    pub public_key: VerifyingKey,
}

impl TweakedKeypair {
    pub fn derive_public_key(spend_public: &VerifyingKey, tweak_scalar: &Scalar) -> Self {
        let spend_point = spend_public.to_bytes();
        let tweak_point = ED25519_BASEPOINT_TABLE * tweak_scalar;

        let mut tweaked_bytes = [0u8; 32];
        let spend_compressed =
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&spend_point).unwrap();
        let spend_point_decompressed = spend_compressed.decompress().unwrap();
        let tweaked_point = spend_point_decompressed + tweak_point;
        tweaked_bytes.copy_from_slice(tweaked_point.compress().as_bytes());

        let tweaked_public = VerifyingKey::from_bytes(&tweaked_bytes).unwrap();
        TweakedKeypair {
            private: None,
            public_key: tweaked_public,
        }
    }

    pub fn derive_keypair(spend_keypair: &SpendKeypair, tweak_scalar: &Scalar) -> Self {
        let tweaked_scalar = spend_keypair.a_scalar() + tweak_scalar;

        let spend_point = spend_keypair.public_key.to_bytes();
        let tweak_point = ED25519_BASEPOINT_TABLE * tweak_scalar;
        let spend_compressed =
            curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&spend_point).unwrap();
        let spend_point_decompressed = spend_compressed.decompress().unwrap();
        let tweaked_point = spend_point_decompressed + tweak_point;
        let tweaked_public_bytes = tweaked_point.compress();
        let tweaked_public = VerifyingKey::from_bytes(tweaked_public_bytes.as_bytes()).unwrap();

        let tweaked_prefix = derive_tweaked_prefix(&spend_keypair.prefix(), &tweaked_public);

        TweakedKeypair {
            private: Some(TweakedPrivate {
                a_scalar: tweaked_scalar,
                prefix: tweaked_prefix,
            }),
            public_key: tweaked_public,
        }
    }
}

pub fn derive_tweak_scalar(discovery_secret: &[u8; 32]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"mithras-tweak-scalar");
    hasher.update(discovery_secret);
    let hash = hasher.finalize();

    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[..32]);
    Scalar::from_bytes_mod_order(scalar_bytes)
}

pub fn derive_tweaked_prefix(base_prefix: &[u8; 32], tweaked_public: &VerifyingKey) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"mithras-tweaked-prefix");
    hasher.update(base_prefix);
    hasher.update(tweaked_public.to_bytes());
    let hash = hasher.finalize();

    let mut tweaked_prefix = [0u8; 32];
    tweaked_prefix.copy_from_slice(&hash[32..64]);
    tweaked_prefix
}
