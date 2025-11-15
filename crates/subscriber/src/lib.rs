use algod_client::{
    AlgodClient,
    models::{BlockAppEvalDelta, SignedTxnInBlock},
};
use algokit_transact::AppCallTransactionFields;
use base64::{Engine as _, engine::general_purpose};
use crossbeam_channel::Sender;
use indexer_client::{IndexerClient, models::Transaction as IndexerTransaction};

pub struct SubscribedTxn {
    pub matched_txn: SignedTxnInBlock,
    pub root_txn: SignedTxnInBlock,
}

fn convert_indexer_txn(indexer_txn: IndexerTransaction) -> SignedTxnInBlock {
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
        application_id: indexer_txn
            .application_transaction
            .map(|app_txn| app_txn.application_id),
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
                    .map(convert_indexer_txn)
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
    pub txn_channel: Sender<SubscribedTxn>,
}

pub struct Subscriber {
    algod: AlgodClient,
    indexer: IndexerClient,
    subscriptions: Vec<TransactionSubscription>,
    last_round: u64,
}

impl Subscriber {
    pub fn new(algod: AlgodClient, indexer: IndexerClient, initial_round: u64) -> Self {
        Subscriber {
            algod,
            indexer,
            subscriptions: Vec::new(),
            last_round: initial_round.saturating_sub(1),
        }
    }

    pub fn subscribe(&mut self, sub: TransactionSubscription) {
        self.subscriptions.push(sub);
    }

    fn filter_sub(
        txns: &[SignedTxnInBlock],
        sub: &TransactionSubscription,
        root: SignedTxnInBlock,
        mut matches: Vec<SubscribedTxn>,
    ) -> Vec<SubscribedTxn> {
        for txn in txns {
            if let Some(app_id) = sub.app {
                match &txn.application_id {
                    Some(id) if *id != app_id => continue,
                    _ => {}
                }
            }

            matches.push(SubscribedTxn {
                matched_txn: txn.clone(),
                root_txn: root.clone(),
            });
        }

        if let Some(eval_delta) = &root.eval_delta
            && let Some(inner_txns) = &eval_delta.inner_txns
        {
            matches = Subscriber::filter_sub(inner_txns, sub, root.clone(), matches);
        }

        matches
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
                None,
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

    async fn indexer_catchup(&mut self) -> Result<(), String> {
        let algod_round = self
            .algod
            .get_status()
            .await
            .map_err(|e| e.to_string())?
            .last_round;

        let mut found_round_in_indexer = false;
        let mut search_round = algod_round - 1;

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

                let filtered_txns = Subscriber::filter_sub(
                    search_result
                        .transactions
                        .iter()
                        .map(|t| convert_indexer_txn(t.clone()))
                        .collect::<Vec<SignedTxnInBlock>>()
                        .as_slice(),
                    sub,
                    SignedTxnInBlock::default(),
                    vec![],
                );

                for matched in filtered_txns {
                    sub.txn_channel.send(matched).map_err(|e| e.to_string())?;
                }

                next = search_result.next_token;
            }
        }

        Ok(())
    }

    pub async fn start(&mut self) {
        self.indexer_catchup().await.unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_app_subscription() {
        let algod = AlgodClient::localnet();
        let indexer = IndexerClient::localnet();
        let mut subscriber = Subscriber::new(algod, indexer, 0);

        let (txn_sender, txn_receiver) = crossbeam_channel::unbounded();

        let sub = TransactionSubscription {
            app: Some(2166),
            txn_channel: txn_sender,
        };

        subscriber.subscribe(sub.clone());

        subscriber.indexer_catchup().await.unwrap();

        let txn = txn_receiver.try_recv().unwrap();

        assert_eq!(txn.matched_txn.application_id.unwrap(), sub.app.unwrap());
    }
}
