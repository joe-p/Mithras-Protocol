use std::{
    collections::{HashMap, hash_map},
    sync::{Arc, Mutex, atomic::AtomicU64},
};

use algokit_transact::Transaction;
use ed25519_dalek::VerifyingKey;
use mithras_crypto::{
    hpke::{HpkeEnvelope, TransactionMetadata},
    keypairs::{DiscoveryKeypair, SpendSeed, TweakedSigner},
    utxo::UtxoSecrets,
};
use subscriber::{Subscriber, TransactionSubscription};

fn compute_nullifier(utxo: &UtxoSecrets) -> [u8; 32] {
    let nullifier = [0u8; 32];
    let _nullifier_data = [compute_commitment(utxo), utxo.nullifier_secret].concat();

    // TODO: MiMC hash of nullifier
    nullifier
}

fn compute_commitment(utxo: &UtxoSecrets) -> [u8; 32] {
    let commitment = [0u8; 32];
    let _commitment_data = [
        &utxo.spending_secret[..],
        &utxo.nullifier_secret[..],
        &utxo.amount.to_le_bytes(),
        &utxo.tweaked_pubkey.to_bytes(),
    ]
    .concat();

    // TODO: MiMC hash of commitment
    commitment
}

enum MithrasMethod {
    Deposit {
        commitment: [u8; 32],
    },
    Spend {
        nullifier: [u8; 32],
        commitment0: [u8; 32],
        commitment1: [u8; 32],
    },
}

impl MithrasMethod {
    fn from_args(args: &[Vec<u8>]) -> Option<Self> {
        if args.is_empty() {
            return None;
        }

        // TODO: calculate the actual selectors
        match args[0].as_slice() {
            b"deposit" => {
                if args.len() != 4 {
                    return None;
                }

                let commitment: [u8; 32] = args[1][0..32].try_into().ok()?;

                Some(MithrasMethod::Deposit { commitment })
            }
            b"spend" => {
                if args.len() != 4 {
                    return None;
                }

                let commitment0: [u8; 32] = args[1][0..32].try_into().ok()?; // signal[0]
                let commitment1: [u8; 32] = args[1][32..64].try_into().ok()?; // signal[1]
                let nullifier: [u8; 32] = args[1][96..128].try_into().ok()?; // signal[3]

                Some(MithrasMethod::Spend {
                    nullifier,
                    commitment0,
                    commitment1,
                })
            }
            _ => None,
        }
    }

    fn verify_commitment(&self, utxo: &UtxoSecrets) -> bool {
        let commitment = compute_commitment(utxo);
        match self {
            MithrasMethod::Deposit {
                commitment: expected,
            } => *expected == commitment,
            MithrasMethod::Spend {
                nullifier: _,
                commitment0: expected0,
                commitment1: expected1,
            } => *expected0 == commitment || *expected1 == commitment,
        }
    }
}

pub struct MithrasSubscriber {
    pub subscriber: Subscriber,
    pub amount: Arc<AtomicU64>,
    pub addrs: Arc<Mutex<Vec<[u8; 32]>>>,
    pub recorded_utxos: Arc<Mutex<HashMap<[u8; 32], u64>>>,
}

impl MithrasSubscriber {
    pub fn new(
        app_id: u64,
        initial_round: u64,
        stop_round: Option<u64>,
        discovery_keypair: &DiscoveryKeypair,
        spend_seed: &SpendSeed,
    ) -> Self {
        let mut subscriber = Subscriber::new(
            algod_client::AlgodClient::localnet(),
            indexer_client::IndexerClient::localnet(),
            initial_round,
            stop_round,
        );

        let (txn_sender, txn_receiver) = crossbeam_channel::unbounded();

        let sub = TransactionSubscription {
            note: None,
            sender: None,
            app: Some(app_id),
            txn_channel: txn_sender,
            app_args: None,
            id: "outputs".to_string(),
        };

        let discovery_keypair = discovery_keypair.to_owned();

        let amount = Arc::new(AtomicU64::new(0));
        let cloned_amount = amount.clone();

        let addrs = Arc::new(Mutex::new(vec![]));
        let cloned_addrs = addrs.clone();

        let recorded_utxos = Arc::new(Mutex::new(HashMap::new()));
        let cloned_recorded_utxos = recorded_utxos.clone();

        let spend_seed = spend_seed.to_owned();

        std::thread::spawn(move || {
            while let Ok(txn) = txn_receiver.recv() {
                let txn = txn.txn.signed_transaction.transaction;

                let args: Vec<Vec<u8>> = match &txn {
                    Transaction::AppCall(appl) => appl.args.clone().unwrap_or_default(),
                    _ => continue,
                };

                let method = match MithrasMethod::from_args(&args) {
                    Some(method) => method,
                    None => continue,
                };

                // Check if we spend a nullifier we already know about before doing any expensive operations
                match method {
                    MithrasMethod::Spend { nullifier, .. } => {
                        let mut utxos_guard = cloned_recorded_utxos.lock().unwrap();
                        if let hash_map::Entry::Occupied(e) = utxos_guard.entry(nullifier) {
                            cloned_amount.fetch_sub(*e.get(), std::sync::atomic::Ordering::SeqCst);
                            e.remove();
                            continue;
                        }
                    }
                    _ => { /* no-op */ }
                }

                for arg in &args[3..] {
                    let hpke_bytes = match arg.to_owned().try_into() {
                        Ok(bytes) => bytes,
                        Err(_) => continue,
                    };

                    let hpke_envelope = match HpkeEnvelope::from_bytes(&hpke_bytes) {
                        Ok(env) => env,
                        Err(_) => continue,
                    };

                    let header = txn.header();
                    let sender_bytes = header.sender.0;
                    let sender = VerifyingKey::from_bytes(&sender_bytes).unwrap();

                    let txn_metadata = TransactionMetadata {
                        app_id,
                        sender,
                        first_valid: header.first_valid,
                        last_valid: header.last_valid,
                        lease: header.lease.unwrap_or([0u8; 32]),
                        network: mithras_crypto::hpke::SupportedNetwork::Custom(
                            header.genesis_hash.unwrap(),
                        ),
                    };

                    if !hpke_envelope
                        .discovery_check(discovery_keypair.clone().private_key(), &txn_metadata)
                    {
                        continue;
                    }

                    let utxo = UtxoSecrets::from_hpke_envelope(
                        hpke_envelope,
                        &discovery_keypair,
                        &txn_metadata,
                    )
                    .unwrap();

                    if !method.verify_commitment(&utxo) {
                        continue;
                    }

                    let utxo_nullifier = compute_nullifier(&utxo);

                    {
                        let mut utxos_guard = cloned_recorded_utxos.lock().unwrap();

                        if let hash_map::Entry::Vacant(e) = utxos_guard.entry(utxo_nullifier) {
                            e.insert(utxo.amount);
                        } else {
                            continue;
                        }
                    }

                    match TweakedSigner::derive(&spend_seed, &utxo.tweak_scalar) {
                        Ok(signer) => {
                            if *signer.public_key() != utxo.tweaked_pubkey {
                                continue;
                            }
                        }
                        Err(_) => continue,
                    }

                    cloned_amount.fetch_add(utxo.amount, std::sync::atomic::Ordering::SeqCst);

                    cloned_addrs
                        .lock()
                        .unwrap()
                        .push(utxo.tweaked_pubkey.to_bytes())
                }
            }
        });

        subscriber.subscribe(sub);

        Self {
            subscriber,
            amount,
            addrs,
            recorded_utxos,
        }
    }
}
