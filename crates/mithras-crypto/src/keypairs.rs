use curve25519_dalek::scalar::clamp_integer;
use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_TABLE};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey as Ed25519PublicKey};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

use crate::MithrasError;

#[derive(Clone)]
pub struct DiscoveryKeypair {
    private_key: X25519SecretKey,
    public_key: X25519PublicKey,
}

impl DiscoveryKeypair {
    pub fn generate() -> Result<Self, MithrasError> {
        let mut secret_key: [u8; 32] = [0u8; 32];

        getrandom::fill(&mut secret_key)
            .map_err(|e| MithrasError::RandomGeneration { msg: e.to_string() })?;
        let private_key = X25519SecretKey::from(secret_key);
        let public_key = X25519PublicKey::from(&private_key);
        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public_key
    }

    pub fn private_key(&self) -> &X25519SecretKey {
        &self.private_key
    }

    pub fn from_keypair(private_key: [u8; 32], public_key: [u8; 32]) -> Self {
        let private_key = X25519SecretKey::from(private_key);
        let public_key = X25519PublicKey::from(public_key);
        Self {
            private_key,
            public_key,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SpendSeed {
    seed: [u8; 32],
    public_key: Ed25519PublicKey,
}

impl SpendSeed {
    pub fn generate() -> Result<Self, MithrasError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed)
            .map_err(|e| MithrasError::RandomGeneration { msg: e.to_string() })?;

        let sk = SigningKey::from_bytes(&seed);
        let public_key = sk.verifying_key();

        Ok(Self { seed, public_key })
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

    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

#[derive(Debug, Clone)]
pub struct TweakedSigner {
    pub a_scalar: Scalar,
    pub prefix: [u8; 32],
    pubkey: Ed25519PublicKey,
}

impl TweakedSigner {
    pub fn derive(spend_keypair: &SpendSeed, tweak_scalar: &Scalar) -> Result<Self, MithrasError> {
        let tweaked_scalar = spend_keypair.a_scalar() + tweak_scalar;

        let spend_point = spend_keypair.public_key.to_bytes();
        let tweak_point = ED25519_BASEPOINT_TABLE * tweak_scalar;
        let spend_compressed = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(
            &spend_point,
        )
        .map_err(|e| MithrasError::CurvePointDecompression {
            msg: format!("Failed to create compressed point from slice: {}", e),
        })?;
        let spend_point_decompressed =
            spend_compressed
                .decompress()
                .ok_or(MithrasError::CurvePointDecompression {
                    msg: "Failed to decompress Edwards point".to_string(),
                })?;
        let tweaked_point = spend_point_decompressed + tweak_point;
        let tweaked_public_bytes = tweaked_point.compress();
        let tweaked_public = Ed25519PublicKey::from_bytes(tweaked_public_bytes.as_bytes())
            .map_err(|e| MithrasError::Ed25519KeyParsing { msg: e.to_string() })?;

        let tweaked_prefix = derive_tweaked_prefix(&spend_keypair.prefix(), &tweaked_public);

        Ok(Self {
            a_scalar: tweaked_scalar,
            prefix: tweaked_prefix,
            pubkey: tweaked_public,
        })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature, MithrasError> {
        let a_g = (ED25519_BASEPOINT_TABLE * &self.a_scalar)
            .compress()
            .to_bytes();
        let public_locked = Ed25519PublicKey::from_bytes(&a_g)
            .map_err(|e| MithrasError::Ed25519KeyParsing { msg: e.to_string() })?;

        let esk = ed25519_dalek::hazmat::ExpandedSecretKey {
            scalar: self.a_scalar,
            hash_prefix: self.prefix,
        };
        Ok(ed25519_dalek::hazmat::raw_sign::<Sha512>(
            &esk,
            msg,
            &public_locked,
        ))
    }

    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.pubkey
    }
}

pub fn derive_tweaked_pubkey(
    spend_public: &Ed25519PublicKey,
    tweak_scalar: &Scalar,
) -> Result<Ed25519PublicKey, MithrasError> {
    let spend_point = spend_public.to_bytes();
    let tweak_point = ED25519_BASEPOINT_TABLE * tweak_scalar;

    let mut tweaked_bytes = [0u8; 32];
    let spend_compressed = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&spend_point)
        .map_err(|e| MithrasError::CurvePointDecompression {
            msg: format!("Failed to create compressed point from slice: {}", e),
        })?;
    let spend_point_decompressed =
        spend_compressed
            .decompress()
            .ok_or(MithrasError::CurvePointDecompression {
                msg: "Failed to decompress Edwards point".to_string(),
            })?;
    let tweaked_point = spend_point_decompressed + tweak_point;
    tweaked_bytes.copy_from_slice(tweaked_point.compress().as_bytes());

    Ed25519PublicKey::from_bytes(&tweaked_bytes)
        .map_err(|e| MithrasError::Ed25519KeyParsing { msg: e.to_string() })
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

pub fn derive_tweaked_prefix(
    base_prefix: &[u8; 32],
    tweaked_public: &Ed25519PublicKey,
) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"mithras-tweaked-prefix");
    hasher.update(base_prefix);
    hasher.update(tweaked_public.to_bytes());
    let hash = hasher.finalize();

    let mut tweaked_prefix = [0u8; 32];
    tweaked_prefix.copy_from_slice(&hash[32..64]);
    tweaked_prefix
}
