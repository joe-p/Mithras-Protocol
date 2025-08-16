use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as B64};
use curve25519_dalek::scalar::clamp_integer;
use curve25519_dalek::{Scalar, constants::ED25519_BASEPOINT_TABLE};
use ed25519_dalek::Signature;
use ed25519_dalek::Verifier;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hpke_rs::Hpke;
use hpke_rs_libcrux::HpkeLibcrux;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use bech32::{self, Hrp};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MithrasAddr {
    pub version: u8,
    pub network: u8,
    pub suite: u8,
    pub spend_ed25519: [u8; 32],
    pub disc_x25519: [u8; 32],
}

impl MithrasAddr {
    pub fn encode(&self) -> String {
        let mut data = Vec::<u8>::with_capacity(3 + 32 + 32);
        data.push(self.version);
        data.push(self.network);
        data.push(self.suite);
        data.extend_from_slice(&self.spend_ed25519);
        data.extend_from_slice(&self.disc_x25519);
        bech32::encode::<bech32::Bech32m>(Hrp::parse_unchecked("mith"), &data).unwrap()
    }

    pub fn decode(s: &str) -> Result<Self> {
        let (hrp, data) = bech32::decode(s)?;
        if hrp.as_str() != "mith" {
            return Err(anyhow!(
                "invalid human-readable prefix. Got {}, expected mith",
                hrp
            ));
        }
        let version = data[0];
        let network = data[1];
        let suite = data[2];
        let spend = data[3..35].try_into()?;
        let disc = data[35..67].try_into()?;
        Ok(Self {
            version,
            network,
            suite,
            spend_ed25519: spend,
            disc_x25519: disc,
        })
    }

    pub fn from_keys(
        spend: &VerifyingKey,
        disc: &X25519PublicKey,
        version: u8,
        network: u8,
        suite: u8,
    ) -> Self {
        let spend_bytes = spend.to_bytes();
        let disc_bytes = disc.as_bytes();
        Self {
            version,
            network,
            suite,
            spend_ed25519: spend_bytes,
            disc_x25519: *disc_bytes,
        }
    }
}

fn suite() -> Hpke<HpkeLibcrux> {
    Hpke::new(
        hpke_rs::Mode::Base,
        hpke_rs::hpke_types::KemAlgorithm::DhKem25519,
        hpke_rs::hpke_types::KdfAlgorithm::HkdfSha512,
        hpke_rs::hpke_types::AeadAlgorithm::ChaCha20Poly1305,
    )
}

/// Wire-format envelope you can store on-chain / send over the network.
/// Keep it versioned so you can rotate suites/keys later.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HpkeEnvelope {
    ver: u8,                  // app version (yours)
    suite: u8,                // your enum code for the chosen suite
    key_id: u32,              // which recipient key (for rotation)
    encapsulated_key: String, // KEM "enc" (ephemeral pubkey) bytes, base64
    ct_b64: String,           // ciphertext||tag, base64
}

#[derive(Debug, Clone)]
struct SpendKeypair {
    seed: [u8; 32],
    public_key: VerifyingKey,
}

struct DiscoveryKeypair {
    private_key: StaticSecret,
    public_key: X25519PublicKey,
}

#[derive(Debug, Clone)]
struct TweakedKeypair {
    // Receiver learns a' = (a + h) mod q with the same prefix
    private: Option<TweakedPrivate>,
    public_key: VerifyingKey,
}

#[derive(Debug, Clone)]
/// The private part of a tweaked keypair. We don't have the original seed, so we store
/// the scalar and prefix directly.
struct TweakedPrivate {
    a_scalar: Scalar,
    prefix: [u8; 32],
}

impl SpendKeypair {
    fn generate() -> Self {
        // Generate a random Ed25519 secret seed and build a SigningKey
        use rand::RngCore as _;
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let public_key = sk.verifying_key();

        Self { seed, public_key }
    }

    fn a_scalar(&self) -> Scalar {
        // Expand the seed like Ed25519: SHA-512(seed) => (a_bytes, prefix)
        let digest = Sha512::digest(self.seed);
        let mut a_bytes = [0u8; 32];
        a_bytes.copy_from_slice(&digest[..32]);
        // Clamp per Ed25519 rules and reduce to scalar as dalek does internally
        Scalar::from_bytes_mod_order(clamp_integer(a_bytes))
    }

    fn prefix(&self) -> [u8; 32] {
        // Expand the seed like Ed25519: SHA-512(seed) => (a_bytes, prefix)
        let digest = Sha512::digest(self.seed);
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&digest[32..64]);
        prefix
    }
}

impl DiscoveryKeypair {
    fn generate() -> Self {
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = X25519PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }
}

fn compute_discovery_secret_sender(
    ephemeral_private: &StaticSecret,
    discovery_public: &X25519PublicKey,
) -> [u8; 32] {
    let shared_secret = ephemeral_private.diffie_hellman(discovery_public);
    *shared_secret.as_bytes()
}

fn compute_discovery_secret_receiver(
    discovery_private: &StaticSecret,
    ephemeral_public: &X25519PublicKey,
) -> [u8; 32] {
    let shared_secret = discovery_private.diffie_hellman(ephemeral_public);
    *shared_secret.as_bytes()
}

fn derive_tweak_scalar(discovery_secret: &[u8; 32]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(b"mithras-tweak-scalar");
    hasher.update(discovery_secret);
    let hash = hasher.finalize();

    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[..32]);
    Scalar::from_bytes_mod_order(scalar_bytes)
}

fn derive_tweaked_prefix(base_prefix: &[u8; 32], tweaked_public: &VerifyingKey) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"mithras-tweaked-prefix");
    hasher.update(base_prefix);
    hasher.update(tweaked_public.to_bytes());
    let hash = hasher.finalize();

    let mut tweaked_prefix = [0u8; 32];
    tweaked_prefix.copy_from_slice(&hash[32..64]);
    tweaked_prefix
}

fn compute_tweaked_keypair_sender(
    spend_public: &VerifyingKey,
    tweak_scalar: &Scalar,
) -> TweakedKeypair {
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

fn compute_tweaked_keypair_receiver(spend: &SpendKeypair, tweak_scalar: &Scalar) -> TweakedKeypair {
    // a' = (a + h) mod q
    let tweaked_scalar = spend.a_scalar() + tweak_scalar;

    // P' = P + h·G
    let spend_point = spend.public_key.to_bytes();
    let tweak_point = ED25519_BASEPOINT_TABLE * tweak_scalar;
    let spend_compressed =
        curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&spend_point).unwrap();
    let spend_point_decompressed = spend_compressed.decompress().unwrap();
    let tweaked_point = spend_point_decompressed + tweak_point;
    let tweaked_public_bytes = tweaked_point.compress();
    let tweaked_public = VerifyingKey::from_bytes(tweaked_public_bytes.as_bytes()).unwrap();

    // Derive per-tweaked-key nonce prefix to prevent cross-key linkability
    let tweaked_prefix = derive_tweaked_prefix(&spend.prefix(), &tweaked_public);

    TweakedKeypair {
        private: Some(TweakedPrivate {
            a_scalar: tweaked_scalar,
            prefix: tweaked_prefix,
        }),
        public_key: tweaked_public,
    }
}

fn ed25519_sign_with_tweaked(tweaked_priv: &TweakedPrivate, msg: &[u8]) -> Signature {
    // Recompute A' = a'·G internally
    let a_g = (ED25519_BASEPOINT_TABLE * &tweaked_priv.a_scalar)
        .compress()
        .to_bytes();
    let public_locked =
        VerifyingKey::from_bytes(&a_g).expect("derived verifying key must be valid");

    // Sign with the locked public
    let esk = ed25519_dalek::hazmat::ExpandedSecretKey {
        scalar: tweaked_priv.a_scalar,
        hash_prefix: tweaked_priv.prefix,
    };
    ed25519_dalek::hazmat::raw_sign::<Sha512>(&esk, msg, &public_locked)
}

fn compute_discovery_tag(
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

fn main() -> anyhow::Result<()> {
    println!("=== Mithras Protocol Demo ===\n");

    // -------- Generate long-term keypairs --------
    println!("1. Generating long-term keypairs...");
    let spend_keypair = SpendKeypair::generate();
    let discovery_keypair = DiscoveryKeypair::generate();

    println!(
        "   Spend public key: {}",
        B64.encode(spend_keypair.public_key.to_bytes())
    );
    println!(
        "   Discovery public key: {}\n",
        B64.encode(discovery_keypair.public_key.as_bytes())
    );

    // -------- Sender side: Generate ephemeral keypair and compute tweaked keypair --------
    println!("2. Sender side operations...");
    let ephemeral_keypair = DiscoveryKeypair::generate();
    println!("   Generated ephemeral keypair");
    println!(
        "   Ephemeral public key (R): {}",
        B64.encode(ephemeral_keypair.public_key.as_bytes())
    );

    // Compute discovery secret (sender side: r * D)
    let discovery_secret_sender = compute_discovery_secret_sender(
        &ephemeral_keypair.private_key,
        &discovery_keypair.public_key,
    );
    println!(
        "   Computed discovery secret: {}",
        B64.encode(discovery_secret_sender)
    );

    // Derive tweak scalar
    let tweak_scalar = derive_tweak_scalar(&discovery_secret_sender);
    println!("   Derived tweak scalar");

    // Compute tweaked keypair (sender can only compute public key)
    let tweaked_keypair_sender =
        compute_tweaked_keypair_sender(&spend_keypair.public_key, &tweak_scalar);
    println!(
        "   Computed tweaked public key (P'): {}",
        B64.encode(tweaked_keypair_sender.public_key.to_bytes())
    );

    // Compute discovery tag
    let sender_data = b"sender_identifier";
    let discovery_tag =
        compute_discovery_tag(&discovery_secret_sender, sender_data, 1000, 2000, 3600);
    println!(
        "   Computed discovery tag: {}\n",
        B64.encode(&discovery_tag)
    );

    // -------- Receiver side: Compute discovery secret and full tweaked keypair --------
    println!("3. Receiver side operations...");

    // Compute discovery secret (receiver side: d * R)
    let discovery_secret_receiver = compute_discovery_secret_receiver(
        &discovery_keypair.private_key,
        &ephemeral_keypair.public_key,
    );
    println!(
        "   Computed discovery secret: {}",
        B64.encode(discovery_secret_receiver)
    );

    // Verify discovery secrets match
    assert_eq!(discovery_secret_sender, discovery_secret_receiver);
    println!("   ✓ Discovery secrets match");

    // Derive same tweak scalar
    let tweak_scalar_receiver = derive_tweak_scalar(&discovery_secret_receiver);
    assert_eq!(tweak_scalar, tweak_scalar_receiver);
    println!("   ✓ Tweak scalars match");

    // Compute full tweaked keypair (receiver can compute both public and private keys)
    let tweaked_keypair_receiver = compute_tweaked_keypair_receiver(&spend_keypair, &tweak_scalar);

    // Verify tweaked public keys match
    assert_eq!(
        tweaked_keypair_sender.public_key.to_bytes(),
        tweaked_keypair_receiver.public_key.to_bytes()
    );
    println!("   ✓ Tweaked public keys match");
    println!("   Computed tweaked private key (a')");

    // Verify discovery tag
    let discovery_tag_receiver =
        compute_discovery_tag(&discovery_secret_receiver, sender_data, 1000, 2000, 3600);
    assert_eq!(discovery_tag, discovery_tag_receiver);
    println!("   ✓ Discovery tags match\n");

    // -------- Ed25519 signing with tweaked key --------
    println!("4. Ed25519 signing with tweaked key...");
    let msg = b"example spend authorization";
    let tweaked_priv = tweaked_keypair_receiver.private.as_ref().unwrap();
    let sig = ed25519_sign_with_tweaked(tweaked_priv, msg);
    // Verify using standard verifier under A'
    // Prefer strict verification if available
    let verify_res = tweaked_keypair_receiver.public_key.verify_strict(msg, &sig);
    if verify_res.is_ok() {
        println!("   ✓ Signature verified with tweaked public key");
    } else {
        // Fallback to non-strict verify for older builds
        tweaked_keypair_receiver.public_key.verify(msg, &sig)?;
        println!("   ✓ Signature verified with tweaked public key");
    }

    // -------- HPKE encryption of spend secret --------
    println!("5. HPKE encryption of spend secret...");

    let mut hpke = suite();
    let hpke_recipient = hpke.generate_key_pair().unwrap();

    let info = b"mithras|network:mainnet|app:1337|v:1";
    let aad = b"txid:BLAH...BLAH";

    let (encapsulated_key, mut sender_ctx) = hpke
        .setup_sender(hpke_recipient.public_key(), info, None, None, None)
        .unwrap();

    let spend_secret = [42u8; 64];
    let ct = sender_ctx.seal(aad, spend_secret.as_ref()).unwrap();

    let env = HpkeEnvelope {
        ver: 1,
        suite: 1,
        key_id: 0,
        encapsulated_key: B64.encode(&encapsulated_key),
        ct_b64: B64.encode(&ct),
    };

    let json = serde_json::to_string(&env)?;
    println!("   Encrypted spend secret envelope created");

    // -------- HPKE decryption --------
    let env2: HpkeEnvelope = serde_json::from_str(&json)?;
    let enclosed_key_bytes = B64.decode(&env2.encapsulated_key)?;
    let ct_bytes = B64.decode(&env2.ct_b64)?;

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

    assert_eq!(&pt, &spend_secret);
    println!("   ✓ Spend secret decrypted successfully\n");

    // -------- Encode Mithras address --------
    println!("6. Encoding Mithras address...");
    let mithras_addr = MithrasAddr::from_keys(
        &tweaked_keypair_receiver.public_key,
        &discovery_keypair.public_key,
        1, // version
        0, // network
        1, // suite
    );

    let encoded_addr = mithras_addr.encode();
    println!("   Encoded Mithras address: {encoded_addr}");

    // -------- Decode Mithras address --------
    println!("7. Decoding Mithras address...");
    let decoded_addr = MithrasAddr::decode(&encoded_addr);
    let addr = decoded_addr?;
    println!("   Decoded Mithras address: {addr:?}");
    assert_eq!(addr.version, mithras_addr.version);
    assert_eq!(addr.network, mithras_addr.network);
    assert_eq!(addr.suite, mithras_addr.suite);
    assert_eq!(addr.spend_ed25519, mithras_addr.spend_ed25519);
    assert_eq!(addr.disc_x25519, mithras_addr.disc_x25519);
    println!("   ✓ Mithras address encoded and decoded successfully\n");

    println!("=== All operations completed successfully! ===");

    Ok(())
}
