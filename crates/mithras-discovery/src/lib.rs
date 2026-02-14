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
    let commitment = [0u8; 32];
    let nullifier = [0u8; 32];
    let _commitment_data = [
        &utxo.spending_secret[..],
        &utxo.nullifier_secret[..],
        &utxo.amount.to_le_bytes(),
        &utxo.tweaked_pubkey.to_bytes(),
    ]
    .concat();

    // TODO: MiMC hash of commitment
    let _nullifier_data = [commitment, utxo.nullifier_secret].concat();

    // TODO: MiMC hash of nullifier
    nullifier
}

enum MithrasMethod {
    Deposit,
    Spend,
}

impl MithrasMethod {
    fn from_method_selector(args: &[u8]) -> Option<Self> {
        if args.is_empty() {
            return None;
        }

        // TODO: calculate the actual selectors
        match args {
            b"deposit" => Some(MithrasMethod::Deposit),
            b"spend" => Some(MithrasMethod::Spend),
            _ => None,
        }
    }
}

pub struct MithrasSubscriber {
    pub subscriber: Subscriber,
    amount: Arc<AtomicU64>,
    addrs: Arc<Mutex<Vec<[u8; 32]>>>,
    recorded_utxos: Arc<Mutex<HashMap<[u8; 32], u64>>>,
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

                    let utxo_nullifier = compute_nullifier(&utxo);

                    {
                        let mut utxos_guard = cloned_recorded_utxos.lock().unwrap();

                        if let hash_map::Entry::Vacant(e) = utxos_guard.entry(utxo_nullifier) {
                            e.insert(utxo.amount);
                        } else {
                            continue;
                        }
                    }

                    // TODO: Checks before adding UTXO amount
                    // - Ensure UTXO commitment matches the one in the app args

                    match MithrasMethod::from_method_selector(&args[0]) {
                        Some(MithrasMethod::Deposit) => {
                            // TODO: Check that commitment matches the one in the first app arg
                        }

                        Some(MithrasMethod::Spend) => {
                            // TODO: Check that the commitment matche the one in the corresponding
                            // (first or second) app arg
                        }
                        None => continue,
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

                    // TODO: Add subscription to spends from the tweaked_pubkey
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
