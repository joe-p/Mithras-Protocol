use algod_client::AlgodClient;
use anyhow::{Result, anyhow};
use kmd_client::{
    KmdClient,
    models::{InitWalletHandleTokenRequest, ListKeysRequest},
};

pub async fn find_wallet(
    kmd: KmdClient,
    wallet_name: &str,
    address_to_find: Option<&str>,
) -> Result<Vec<u8>> {
    let wallets_response = kmd.list_wallets().await?;

    let wallets = wallets_response
        .wallets
        .ok_or(anyhow!("no wallets found"))?;

    let wallet = wallets
        .into_iter()
        .find(|w| w.name.as_deref() == Some(wallet_name))
        .ok_or(anyhow!("wallet not found"))?;

    let wallet_handle_response = kmd
        .init_wallet_handle_token(InitWalletHandleTokenRequest {
            wallet_id: wallet.id.clone(),
            wallet_password: None,
        })
        .await?;

    let wallet_handle_token = wallet_handle_response.wallet_handle_token.clone();

    let keys_in_wallet_response = kmd
        .list_keys_in_wallet(ListKeysRequest {
            wallet_handle_token: wallet_handle_token.clone(),
        })
        .await?;

    // Use the first address if no specific address to find is provided
    let address_to_export = keys_in_wallet_response
        .addresses
        .clone()
        .ok_or(anyhow!("no addresses found in wallet"))?
        .first()
        .ok_or(anyhow!("no addresses found in wallet"))?
        .to_string();

    if address_to_find.is_some()
        && !keys_in_wallet_response
            .addresses
            .ok_or(anyhow!("no addresses found in wallet"))?
            .contains(&address_to_export.to_string())
    {
        return Err(anyhow!("address not found in wallet"));
    }

    let export_key_response = kmd
        .export_key(kmd_client::models::ExportKeyRequest {
            address: Some(address_to_export),
            wallet_handle_token,
            wallet_password: None,
        })
        .await;

    match export_key_response {
        Ok(resp) => resp.private_key.ok_or(anyhow!("no private key found")),
        Err(_) => Err(anyhow!("failed to export key")),
    }
}

pub async fn get_dispenser_account(algod: AlgodClient, kmd: KmdClient) -> Result<Vec<u8>> {
    let genesis_response = algod.get_genesis().await?;

    let dispenser_addresses: Vec<String> = genesis_response
        .alloc
        .into_iter()
        .filter(|a| a.comment == "Wallet1")
        .map(|a| a.addr)
        .collect();

    if !dispenser_addresses.is_empty() {
        let dispenser = find_wallet(
            kmd,
            "unencrypted-default-wallet",
            Some(&dispenser_addresses[0]),
        )
        .await;

        if dispenser.is_ok() {
            return dispenser;
        }
    }

    Err(anyhow!(
        "Error retrieving LocalNet dispenser account; couldn't find the default account in KMD"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_find_wallet() {
        let kmd = KmdClient::localnet();

        let wallet_name = "unencrypted-default-wallet";

        let result = find_wallet(kmd, wallet_name, None).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_dispenser_account() {
        let algod = AlgodClient::localnet();
        let kmd = KmdClient::localnet();

        let result = get_dispenser_account(algod, kmd).await;

        result.unwrap();
    }
}
