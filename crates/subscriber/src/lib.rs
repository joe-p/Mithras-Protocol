use std::collections::HashMap;

use algod_client::{
    AlgodClient,
    models::{BlockAppEvalDelta, SignedTxnInBlock},
};
use algokit_transact::AppCallTransactionFields;
use base64::{Engine as _, engine::general_purpose};
use crossbeam_channel::Sender;
use indexer_client::{IndexerClient, models::Transaction as IndexerTransaction};

pub struct SubscriberTxn {
    pub txn: SignedTxnInBlock,
    pub root_txn: SignedTxnInBlock,
    pub intra_round_offset: Option<u64>,
    pub confirmed_round: Option<u64>,
}

fn indexer_to_subscriber_txn(
    indexer_txn: IndexerTransaction,
    root_txn: SignedTxnInBlock,
) -> SubscriberTxn {
    let intra_round_offset = indexer_txn.intra_round_offset;
    let confirmed_round = indexer_txn.confirmed_round;
    SubscriberTxn {
        txn: indexer_to_algod(indexer_txn),
        root_txn,
        intra_round_offset,
        confirmed_round,
    }
}

fn indexer_to_algod(indexer_txn: IndexerTransaction) -> SignedTxnInBlock {
    let header: algokit_transact::TransactionHeader = algokit_transact::TransactionHeader {
        sender: indexer_txn.sender.parse().unwrap_or_default(),
        fee: Some(indexer_txn.fee),
        // TODO: Fix indexer returning u32 here
        first_valid: indexer_txn.first_valid as u64,
        last_valid: indexer_txn.last_valid as u64,
        genesis_hash: indexer_txn.genesis_hash.clone().map(|gh| {
            gh.try_into()
                .expect("all genesis hashes should be 32 bytes")
        }),
        genesis_id: indexer_txn.genesis_id.clone(),
        note: indexer_txn
            .note
            .map(|n| general_purpose::STANDARD.decode(n).unwrap_or_default()),
        rekey_to: indexer_txn.rekey_to.and_then(|addr| addr.parse().ok()),
        lease: indexer_txn
            .lease
            .map(|l| l.try_into().expect("all leases should be 32 bytes")),
        group: indexer_txn
            .group
            .map(|g| g.try_into().expect("all groups should be 32 bytes")),
    };

    let txn: algokit_transact::Transaction = match indexer_txn.tx_type.as_str() {
        "appl" => {
            let appl_txn = indexer_txn
                .application_transaction
                .clone()
                .expect("application transaction missing")
                .clone();

            algokit_transact::Transaction::AppCall(AppCallTransactionFields {
                header,
                app_id: indexer_txn
                    .application_transaction
                    .as_ref()
                    .map_or(0, |app_txn| app_txn.application_id),
                account_references: appl_txn.accounts.map(|accounts_vec| {
                    accounts_vec
                        .iter()
                        .map(|acc| acc.parse().unwrap_or_default())
                        .collect()
                }),
                app_references: appl_txn.foreign_apps,
                asset_references: appl_txn.foreign_assets,
                // TODO: conversion function for on_complete
                on_complete: unsafe {
                    std::mem::transmute::<u8, algokit_transact::OnApplicationComplete>(
                        appl_txn.on_completion as u8,
                    )
                },
                args: appl_txn.application_args.map(|args_vec| {
                    args_vec
                        .iter()
                        .map(|arg| general_purpose::STANDARD.decode(arg).unwrap_or_default())
                        .collect()
                }),
                approval_program: appl_txn.approval_program,
                clear_state_program: appl_txn.clear_state_program,
                extra_program_pages: appl_txn.extra_program_pages,
                global_state_schema: appl_txn.global_state_schema.map(|schema| {
                    algokit_transact::StateSchema {
                        num_uints: schema.num_uint,
                        num_byte_slices: schema.num_byte_slice,
                    }
                }),
                local_state_schema: appl_txn.local_state_schema.map(|schema| {
                    algokit_transact::StateSchema {
                        num_uints: schema.num_uint,
                        num_byte_slices: schema.num_byte_slice,
                    }
                }),
                box_references: appl_txn.box_references.map(|boxes| {
                    boxes
                        .iter()
                        .map(|b| algokit_transact::BoxReference {
                            app_id: b.app,
                            name: b.name.clone(),
                        })
                        .collect()
                }),
            })
        }
        "acfg" => {
            let acfg_txn = indexer_txn
                .asset_config_transaction
                .clone()
                .expect("asset config transaction missing")
                .clone();

            algokit_transact::Transaction::AssetConfig(
                algokit_transact::AssetConfigTransactionFields {
                    header,
                    asset_id: acfg_txn.asset_id.unwrap_or(0),
                    asset_name: acfg_txn.params.as_ref().and_then(|p| p.name.clone()),

                    unit_name: acfg_txn.params.as_ref().and_then(|p| p.unit_name.clone()),
                    url: acfg_txn.params.as_ref().and_then(|p| p.url.clone()),
                    clawback: acfg_txn
                        .params
                        .as_ref()
                        .and_then(|p| p.clawback.clone())
                        .and_then(|addr| addr.parse().ok()),
                    manager: acfg_txn
                        .params
                        .as_ref()
                        .and_then(|p| p.manager.clone())
                        .and_then(|addr| addr.parse().ok()),
                    reserve: acfg_txn
                        .params
                        .as_ref()
                        .and_then(|p| p.reserve.clone())
                        .and_then(|addr| addr.parse().ok()),
                    freeze: acfg_txn
                        .params
                        .as_ref()
                        .and_then(|p| p.freeze.clone())
                        .and_then(|addr| addr.parse().ok()),
                    total: acfg_txn.params.as_ref().map(|p| p.total),
                    decimals: acfg_txn.params.as_ref().map(|p| p.decimals),
                    default_frozen: acfg_txn.params.as_ref().and_then(|p| p.default_frozen),
                    // convert metadata hash to 32 array
                    metadata_hash: acfg_txn.params.and_then(|p| p.metadata_hash).map(|mh| {
                        mh.try_into()
                            .expect("all metadata hashes should be 32 bytes")
                    }),
                },
            )
        }
        "axfer" => {
            let axfer_txn = indexer_txn
                .asset_transfer_transaction
                .clone()
                .expect("asset transfer transaction missing")
                .clone();

            algokit_transact::Transaction::AssetTransfer(
                algokit_transact::AssetTransferTransactionFields {
                    header,
                    asset_id: axfer_txn.asset_id,
                    amount: axfer_txn.amount,
                    receiver: axfer_txn.receiver.parse().unwrap_or_default(),
                    close_remainder_to: axfer_txn.close_to.and_then(|addr| addr.parse().ok()),
                    asset_sender: axfer_txn.sender.and_then(|addr| addr.parse().ok()),
                },
            )
        }
        "pay" => {
            let pay_txn = indexer_txn
                .payment_transaction
                .clone()
                .expect("payment transaction missing")
                .clone();

            algokit_transact::Transaction::Payment(algokit_transact::PaymentTransactionFields {
                header,
                amount: pay_txn.amount,
                receiver: pay_txn.receiver.parse().unwrap_or_default(),
                close_remainder_to: pay_txn
                    .close_remainder_to
                    .and_then(|addr| addr.parse().ok()),
            })
        }
        _ => {
            // Handle other types or default case
            todo!("support for '{}' txn type", indexer_txn.tx_type);
        }
    };

    // TODO: handle sig/msig
    let stxn = algokit_transact::SignedTransaction {
        transaction: txn,
        signature: None,
        auth_address: indexer_txn.auth_addr.and_then(|addr| addr.parse().ok()),
        multisignature: None,
    };
    SignedTxnInBlock {
        signed_transaction: stxn,
        application_id: indexer_txn.created_application_index,
        // TODO: handle logic sig
        logic_signature: None,
        asset_closing_amount: indexer_txn
            .asset_transfer_transaction
            .and_then(|t| t.close_amount),
        closing_amount: indexer_txn.closing_amount,
        // TODO: convert deltas
        eval_delta: Some(BlockAppEvalDelta {
            global_delta: None,
            local_deltas: None,
            inner_txns: indexer_txn.inner_txns.map(|itxns| {
                itxns
                    .into_iter()
                    .map(indexer_to_algod)
                    .collect::<Vec<SignedTxnInBlock>>()
            }),
            shared_accounts: None,
            logs: None,
        }),
        has_genesis_hash: Some(indexer_txn.genesis_hash.is_some()),
        has_genesis_id: Some(indexer_txn.genesis_id.is_some()),
        config_asset: indexer_txn
            .asset_config_transaction
            .and_then(|t| t.asset_id),
        receiver_rewards: indexer_txn.receiver_rewards,
        sender_rewards: indexer_txn.sender_rewards,
        close_rewards: indexer_txn.close_rewards,
    }
}

#[derive(Clone)]
pub struct TransactionSubscription {
    pub app: Option<u64>,
    pub app_args: Option<HashMap<u64, Option<Vec<u8>>>>,
    pub txn_channel: Sender<SubscriberTxn>,
}

pub struct Subscriber {
    algod: AlgodClient,
    indexer: IndexerClient,
    subscriptions: Vec<TransactionSubscription>,
    last_round: u64,
    stop_round: Option<u64>,
}

impl Subscriber {
    pub fn new(
        algod: AlgodClient,
        indexer: IndexerClient,
        initial_round: u64,
        stop_round: Option<u64>,
    ) -> Self {
        Subscriber {
            algod,
            indexer,
            subscriptions: Vec::new(),
            last_round: initial_round.saturating_sub(1),
            stop_round,
        }
    }

    pub fn subscribe(&mut self, sub: TransactionSubscription) {
        self.subscriptions.push(sub);
    }

    fn send_matches(
        txns: Vec<SubscriberTxn>,
        sub: &TransactionSubscription,
        root_txn: SignedTxnInBlock,
        genesis_hash: [u8; 32],
        genesis_id: String,
    ) -> Result<(), String> {
        for subscriber_txn in txns {
            let mut txn = subscriber_txn.txn;
            txn.signed_transaction
                .transaction
                .header_mut()
                .genesis_hash
                .get_or_insert(genesis_hash);

            txn.signed_transaction
                .transaction
                .header_mut()
                .genesis_id
                .get_or_insert(genesis_id.clone());

            if let Some(subbed_app_id) = sub.app {
                match &txn.application_id {
                    Some(id) if *id != subbed_app_id => continue,
                    _ => {}
                }
            }

            if let Some(subbed_app_args) = &sub.app_args {
                let appl_txn = match &txn.signed_transaction.transaction {
                    algokit_transact::Transaction::AppCall(fields) => fields,
                    _ => continue,
                };

                let mut args_match = true;

                for (arg_idx, expected_arg) in subbed_app_args {
                    let actual_arg = appl_txn
                        .args
                        .as_ref()
                        .and_then(|args| args.get(*arg_idx as usize));

                    if actual_arg != expected_arg.as_ref() {
                        args_match = false;
                        break;
                    }
                }

                if !args_match {
                    continue;
                }
            }

            sub.txn_channel
                .try_send(SubscriberTxn {
                    txn: txn.clone(),
                    root_txn: root_txn.clone(),
                    intra_round_offset: subscriber_txn.intra_round_offset,
                    confirmed_round: subscriber_txn.confirmed_round,
                })
                .map_err(|e| e.to_string())?;

            if let Some(eval_delta) = txn.eval_delta
                && let Some(inner_txns) = eval_delta.inner_txns
            {
                let inner_subscriber_txns = inner_txns
                    .into_iter()
                    .enumerate()
                    .map(|(idx, mut inner_txn)| {
                        inner_txn
                            .signed_transaction
                            .transaction
                            .header_mut()
                            .genesis_hash
                            .get_or_insert(genesis_hash);

                        inner_txn
                            .signed_transaction
                            .transaction
                            .header_mut()
                            .genesis_id
                            .get_or_insert(genesis_id.clone());
                        SubscriberTxn {
                            txn: inner_txn,
                            root_txn: root_txn.clone(),
                            intra_round_offset: subscriber_txn
                                .intra_round_offset
                                .map(|offset| offset + idx as u64 + 1),
                            confirmed_round: subscriber_txn.confirmed_round,
                        }
                    })
                    .collect::<Vec<SubscriberTxn>>();

                Subscriber::send_matches(
                    inner_subscriber_txns,
                    sub,
                    root_txn.clone(),
                    genesis_hash,
                    genesis_id.clone(),
                )?;
            }
        }

        Ok(())
    }

    async fn indexer_search_sub(
        &self,
        next: Option<&str>,
        min_round: u64,
        sub: &TransactionSubscription,
    ) -> Result<indexer_client::models::SearchForTransactions, String> {
        self.indexer
            .search_for_transactions(
                None,
                next,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(min_round),
                self.stop_round,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                sub.app,
            )
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn indexer_catchup(&mut self) -> Result<(), String> {
        let algod_round = self
            .algod
            .get_status()
            .await
            .map_err(|e| e.to_string())?
            .last_round;

        let block_header = self
            .algod
            .get_block(algod_round, Some(true))
            .await
            .map_err(|e| e.to_string())?
            .block;

        let genesis_hash: [u8; 32] = block_header
            .genesis_hash
            .clone()
            .map(|gh| gh.try_into().unwrap_or_default())
            .unwrap_or_default();

        let genesis_id = block_header.genesis_id.clone().unwrap_or_default();

        let mut search_round = std::cmp::min(self.stop_round.unwrap_or(u64::MAX), algod_round);
        let mut found_round_in_indexer = false;

        while !found_round_in_indexer {
            match self.indexer.lookup_block(search_round, Some(true)).await {
                Ok(_) => {
                    found_round_in_indexer = true;
                }
                Err(_) => {
                    search_round = search_round.saturating_sub(1);
                }
            }
        }

        for sub in &self.subscriptions {
            let mut next: Option<String> = Some(String::new());

            while let Some(ref token) = next {
                let search_result = self
                    .indexer_search_sub(Some(token), self.last_round, sub)
                    .await
                    .map_err(|e| e.to_string())?;

                Subscriber::send_matches(
                    search_result
                        .transactions
                        .into_iter()
                        .map(|t| indexer_to_subscriber_txn(t.clone(), indexer_to_algod(t)))
                        .collect::<Vec<SubscriberTxn>>(),
                    sub,
                    SignedTxnInBlock::default(),
                    genesis_hash,
                    genesis_id.clone(),
                )?;

                next = search_result.next_token;
            }
        }

        Ok(())
    }

    pub async fn algod_catchup(&mut self) -> Result<(), String> {
        let algod_round = self
            .algod
            .get_status()
            .await
            .map_err(|e| e.to_string())?
            .last_round;

        let block_header = self
            .algod
            .get_block(algod_round, Some(true))
            .await
            .map_err(|e| e.to_string())?
            .block;

        let genesis_hash: [u8; 32] = block_header
            .genesis_hash
            .clone()
            .map(|gh| gh.try_into().unwrap_or_default())
            .unwrap_or_default();

        let genesis_id = block_header.genesis_id.clone().unwrap_or_default();
        let stop_round = std::cmp::min(self.stop_round.unwrap_or(u64::MAX), algod_round);

        for round in (self.last_round + 1)..=stop_round {
            let block = self
                .algod
                .get_block(round, Some(false))
                .await
                .map_err(|e| e.to_string())?;

            if let Some(txns) = block.block.transactions {
                for sub in &self.subscriptions {
                    let subscriber_txns = txns
                        .clone()
                        .into_iter()
                        .enumerate()
                        .map(|(idx, txn)| SubscriberTxn {
                            txn: txn.clone(),
                            root_txn: txn.clone(),
                            intra_round_offset: Some(idx as u64),
                            confirmed_round: Some(round),
                        })
                        .collect::<Vec<SubscriberTxn>>();

                    Subscriber::send_matches(
                        subscriber_txns,
                        sub,
                        SignedTxnInBlock::default(),
                        genesis_hash,
                        genesis_id.clone(),
                    )?;
                }
            }

            self.last_round = round;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algokit_transact::TransactionId;
    use crossbeam_channel::Receiver;
    use pretty_assertions::assert_eq;

    const TEST_TXID: &str = "KTN52RWH34JR637HG6R3LIWMIW6R6WV7OSHFFYDFCBTMQ3BAKTGA";

    struct TestSetup {
        subscriber: Subscriber,
        txn_receiver: Receiver<SubscriberTxn>,
        sub: TransactionSubscription,
    }

    async fn setup_app_subscription_test() -> TestSetup {
        let algod = AlgodClient::mainnet();
        let indexer = IndexerClient::mainnet();

        let (txn_sender, txn_receiver) = crossbeam_channel::unbounded();

        let txn = indexer.lookup_transaction(TEST_TXID).await.unwrap();
        let confirmed_round = txn.transaction.confirmed_round.unwrap();

        let mut subscriber = Subscriber::new(
            algod,
            indexer,
            confirmed_round - 1,
            Some(confirmed_round + 1),
        );

        let mut subbed_args: HashMap<u64, Option<Vec<u8>>> = HashMap::new();
        let app_txn = txn.transaction.application_transaction.as_ref().unwrap();
        let b64_arg = app_txn.application_args.as_ref().unwrap().get(1).unwrap();

        subbed_args.insert(1, Some(general_purpose::STANDARD.decode(b64_arg).unwrap()));
        let sub = TransactionSubscription {
            app: Some(app_txn.application_id),
            txn_channel: txn_sender,
            app_args: Some(subbed_args),
        };

        subscriber.subscribe(sub.clone());

        TestSetup {
            subscriber,
            txn_receiver,
            sub,
        }
    }

    fn assert_received_transaction(
        txn_receiver: &Receiver<SubscriberTxn>,
        sub: &TransactionSubscription,
    ) {
        let txn = txn_receiver
            .try_recv()
            .unwrap()
            .txn
            .signed_transaction
            .transaction;

        let app_fields = match &txn {
            algokit_transact::Transaction::AppCall(fields) => fields,
            _ => panic!("expected app call transaction"),
        };

        assert_eq!(app_fields.app_id, sub.app.unwrap());
        assert_eq!(txn.id().unwrap(), TEST_TXID);
    }

    #[tokio::test]
    async fn test_indexer_app_subscription() {
        let TestSetup {
            mut subscriber,
            txn_receiver,
            sub,
        } = setup_app_subscription_test().await;
        subscriber.indexer_catchup().await.unwrap();
        assert_received_transaction(&txn_receiver, &sub);
    }

    #[tokio::test]
    async fn test_algod_app_subscription() {
        let TestSetup {
            mut subscriber,
            txn_receiver,
            sub,
        } = setup_app_subscription_test().await;
        subscriber.algod_catchup().await.unwrap();
        assert_received_transaction(&txn_receiver, &sub);
    }
}
