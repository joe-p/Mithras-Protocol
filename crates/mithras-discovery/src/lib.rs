use std::sync::{Arc, atomic::AtomicU64};

use ed25519_dalek::VerifyingKey;
use mithras_crypto::{
    hpke::{HpkeEnvelope, TransactionMetadata},
    keypairs::DiscoveryKeypair,
    utxo::UtxoSecrets,
};
use subscriber::{Subscriber, TransactionSubscription};

pub struct MithrasSubscriber {
    pub subscriber: Subscriber,
    amount: Arc<AtomicU64>,
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

        std::thread::spawn(move || {
            while let Ok(txn) = txn_receiver.recv() {
                let note = match txn.txn.signed_transaction.transaction.note() {
                    Some(n) => n.to_vec(),
                    None => continue,
                };

                let hpke_bytes = match note.try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => continue,
                };

                let hpke_envelope = match HpkeEnvelope::from_bytes(&hpke_bytes) {
                    Ok(env) => env,
                    Err(_) => continue,
                };

                let sender_bytes = txn.txn.signed_transaction.transaction.header().sender.0;
                let sender = VerifyingKey::from_bytes(&sender_bytes).unwrap();

                let txn_metadata = TransactionMetadata {
                    app_id,
                    sender,
                    first_valid: txn.txn.signed_transaction.transaction.header().first_valid,
                    last_valid: txn.txn.signed_transaction.transaction.header().last_valid,
                    lease: txn
                        .txn
                        .signed_transaction
                        .transaction
                        .header()
                        .lease
                        .unwrap(),
                    network: mithras_crypto::hpke::SupportedNetwork::Custom(
                        txn.txn
                            .signed_transaction
                            .transaction
                            .header()
                            .genesis_hash
                            .unwrap(),
                    ),
                };

                if hpke_envelope
                    .discovery_check(discovery_keypair.clone().private_key(), &txn_metadata)
                {
                    let utxo = UtxoSecrets::from_hpke_envelope(
                        hpke_envelope,
                        &discovery_keypair,
                        &txn_metadata,
                    )
                    .unwrap();

                    cloned_amount.fetch_add(utxo.amount, std::sync::atomic::Ordering::SeqCst);
                }
            }
        });

        subscriber.subscribe(sub);

        Self { subscriber, amount }
    }
}
