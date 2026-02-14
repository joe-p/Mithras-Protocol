use std::sync::{Arc, Mutex, atomic::AtomicU64};

use algokit_transact::Transaction;
use ed25519_dalek::VerifyingKey;
use mithras_crypto::{
    hpke::{HpkeEnvelope, TransactionMetadata},
    keypairs::DiscoveryKeypair,
    utxo::UtxoSecrets,
};
use subscriber::{Subscriber, TransactionSubscription};

fn compute_commitment(utxo: &UtxoSecrets) -> [u8; 32] {
    let commitment = [0u8; 32];
    let _data_to_hash = [
        &utxo.spending_secret[..],
        &utxo.nullifier_secret[..],
        &utxo.amount.to_le_bytes(),
        &utxo.tweaked_pubkey.to_bytes(),
    ]
    .concat();

    // TODO: MiMC hash
    commitment
}

pub struct MithrasSubscriber {
    pub subscriber: Subscriber,
    amount: Arc<AtomicU64>,
    addrs: Arc<Mutex<Vec<[u8; 32]>>>,
    recorded_utxos: Arc<Mutex<Vec<[u8; 32]>>>,
}

impl MithrasSubscriber {
    pub fn new(
        app_id: u64,
        initial_round: u64,
        stop_round: Option<u64>,
        discovery_keypair: &DiscoveryKeypair,
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
        };

        let discovery_keypair = discovery_keypair.to_owned();

        let amount = Arc::new(AtomicU64::new(0));
        let cloned_amount = amount.clone();

        let addrs = Arc::new(Mutex::new(vec![]));
        let cloned_addrs = addrs.clone();

        let recorded_utxos = Arc::new(Mutex::new(vec![]));
        let cloned_recorded_utxos = recorded_utxos.clone();

        std::thread::spawn(move || {
            while let Ok(txn) = txn_receiver.recv() {
                let txn = txn.txn.signed_transaction.transaction;

                let args: Vec<Vec<u8>> = match &txn {
                    Transaction::AppCall(appl) => appl.args.clone().unwrap_or_default(),
                    _ => continue,
                };

                for arg in &args[1..] {
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

                    let utxo_commitment = compute_commitment(&utxo);

                    {
                        let mut utxos_guard = cloned_recorded_utxos.lock().unwrap();

                        if utxos_guard.contains(&utxo_commitment) {
                            continue;
                        } else {
                            utxos_guard.push(utxo_commitment);
                        }
                    }

                    // TODO: Checks before adding UTXO amount
                    // - Ensure we can reconstruct the stealth keypair
                    // - Ensure nullifier isn't already spent on-chain
                    // - Ensure UTXO commitment exists in merkle tree

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
