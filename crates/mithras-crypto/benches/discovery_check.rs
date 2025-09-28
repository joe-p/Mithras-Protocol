use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ed25519_dalek::VerifyingKey;
use mithras_crypto::{
    address::MithrasAddr,
    hpke::{SupportedHpkeSuite, SupportedNetwork, TransactionMetadata},
    keypairs::{DiscoveryKeypair, SpendSeed},
    utxo::UtxoInputs,
};

fn bench_discovery_check_ok(c: &mut Criterion) {
    // One-time setup: generate keys, address, txn, envelope
    let spend = SpendSeed::generate().expect("spend seed");
    let disc = DiscoveryKeypair::generate().expect("discovery keypair");

    let addr = MithrasAddr::from_keys(
        spend.public_key(),
        disc.public_key(),
        1,
        SupportedNetwork::Testnet,
        SupportedHpkeSuite::Base25519Sha512ChaCha20Poly1305,
    );

    let txn = TransactionMetadata {
        sender: VerifyingKey::from_bytes(&[0u8; 32]).expect("sender vk"),
        first_valid: 10,
        last_valid: 20,
        lease: [0u8; 32],
        network: SupportedNetwork::Mainnet,
        app_id: 42,
    };

    let inputs = UtxoInputs::generate(&txn, 12345, &addr).expect("utxo inputs");
    let env = inputs.hpke_envelope;

    c.bench_function("discovery_check_ok", |b| {
        b.iter(|| {
            let ok = env
                .discovery_check(black_box(disc.private_key()), black_box(&txn))
                .expect("discovery_check ok");
            assert!(ok);
        });
    });
}

fn bench_discovery_check_wrong_key(c: &mut Criterion) {
    // One-time setup shared with ok-case but re-created for simplicity
    let spend = SpendSeed::generate().expect("spend seed");
    let disc = DiscoveryKeypair::generate().expect("discovery keypair");

    let addr = MithrasAddr::from_keys(
        spend.public_key(),
        disc.public_key(),
        1,
        SupportedNetwork::Testnet,
        SupportedHpkeSuite::Base25519Sha512ChaCha20Poly1305,
    );

    let txn = TransactionMetadata {
        sender: VerifyingKey::from_bytes(&[0u8; 32]).expect("sender vk"),
        first_valid: 10,
        last_valid: 20,
        lease: [0u8; 32],
        network: SupportedNetwork::Mainnet,
        app_id: 42,
    };

    let inputs = UtxoInputs::generate(&txn, 12345, &addr).expect("utxo inputs");
    let env = inputs.hpke_envelope;

    let wrong_disc = DiscoveryKeypair::generate().expect("wrong discovery keypair");

    c.bench_function("discovery_check_wrong_key", |b| {
        b.iter(|| {
            let ok = env
                .discovery_check(black_box(wrong_disc.private_key()), black_box(&txn))
                .expect("discovery_check wrong");
            assert!(!ok);
        });
    });
}

criterion_group!(
    benches,
    bench_discovery_check_ok,
    bench_discovery_check_wrong_key
);
criterion_main!(benches);
