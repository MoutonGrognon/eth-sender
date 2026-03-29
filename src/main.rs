use alloy::{
    eips::eip1559::{DEFAULT_BASE_FEE_MAX_CHANGE_DENOMINATOR, DEFAULT_ELASTICITY_MULTIPLIER},
    network::TransactionBuilder,
    primitives::U256,
    signers::local::PrivateKeySigner,
    transports::http::reqwest::Url,
};
use alloy_primitives::{Address, LogData};
use alloy_provider::{PendingTransactionError, Provider, ProviderBuilder};
use alloy_rpc_types_eth::{BlockId, Log, ReceiptEnvelope, TransactionReceipt, TransactionRequest};
use hex;
use k256::ecdsa;
use keccak_hash;
use rpassword::read_password;
use std::io::Write;
use substring::{self, Substring};

const WEI: u128 = 1u128;
const G: u128 = 1_000_000_000u128;
const GWEI: u128 = G * WEI;

// True at the time of writing
const ETH_TO_DOLLARS_RATIO_DESCRIPTION: &str = "1ETH ~ 2k$";
const ETH_TO_DOLLARS_RATIO: u128 = 2_000u128;

fn decode_key(hex_key: String) -> Vec<u8> {
    let clean_hex_key: String;
    if hex_key.starts_with("0x") {
        let key_size = hex_key.len();
        clean_hex_key = hex_key.substring(2, key_size).to_string();
    } else {
        clean_hex_key = hex_key;
    }
    let decoded_key =
        hex::decode(&clean_hex_key).expect("Should have extracted bytes from the hex key");

    decoded_key
}

fn get_private_key() -> [u8; 32] {
    println!("Enter / paste your private key (it will remain hidden) :");
    std::io::stdout()
        .flush()
        .expect("Should have flushed stdout");
    let hex_private_key = read_password().expect("Should have read the private key");

    let decoded_private_key = decode_key(hex_private_key);
    let mut raw_private_key = [0; 32];
    let bytes = &decoded_private_key[..raw_private_key.len()];
    raw_private_key.copy_from_slice(bytes);

    raw_private_key
}

fn get_public_address() -> [u8; 20] {
    println!("Enter the receiver's public address :");
    let hex_public_address: String = read_line();

    let decoded_public_address = decode_key(hex_public_address.trim().to_string());
    let mut raw_public_address = [0; 20];
    let bytes = &decoded_public_address[..raw_public_address.len()];
    raw_public_address.copy_from_slice(bytes);

    raw_public_address
}

fn compute_public_key_from_private_key(private_key_bytes: &[u8; 32]) -> [u8; 64] {
    let private_key =
        ecdsa::SigningKey::from_slice(private_key_bytes).expect("Should have generated a key");

    let public_key = private_key.verifying_key();
    let elliptic_point = public_key.to_encoded_point(false);
    let x_bytes = elliptic_point.x().expect("Should have x coordinate");
    let y_bytes = elliptic_point.y().expect("Should have y coordinate");
    let mut public_key_chars = Vec::<u8>::new();
    for char in x_bytes.iter().chain(y_bytes.iter()) {
        public_key_chars.push(*char);
    }

    let mut public_key_bytes = [0; 64];
    let bytes = &public_key_chars[..64];
    public_key_bytes.copy_from_slice(bytes);

    public_key_bytes
}

fn compute_public_address_from_public_key(public_key_bytes: &[u8; 64]) -> [u8; 20] {
    let mut eth_public_key_hash = [0u8; 32];
    keccak_hash::keccak_256(public_key_bytes.as_slice(), &mut eth_public_key_hash);

    let mut public_address_bytes = [0; 20];
    let bytes = &eth_public_key_hash[eth_public_key_hash.len() - 20..eth_public_key_hash.len()];
    public_address_bytes.copy_from_slice(bytes);

    public_address_bytes
}

fn compute_public_address_from_private_key(private_key_bytes: &[u8; 32]) -> [u8; 20] {
    let public_key_bytes = compute_public_key_from_private_key(private_key_bytes);
    let public_address_bytes = compute_public_address_from_public_key(&public_key_bytes);
    public_address_bytes
}

fn calculate_base_fee_per_gas(base_fee: u64, gas_used: u64, gas_limit: u64) -> u128 {
    let gas_target = gas_limit / DEFAULT_ELASTICITY_MULTIPLIER;

    let gas_delta = gas_used as i64 - gas_target as i64;
    let gas_delta_abs = gas_delta.abs() as u64;
    if gas_delta_abs == 0 {
        return base_fee as u128;
    }

    let max_base_fee_change = base_fee / DEFAULT_BASE_FEE_MAX_CHANGE_DENOMINATOR;
    let base_fee_change = max_base_fee_change * (gas_delta_abs / gas_target);

    if gas_delta > 0 {
        (base_fee + base_fee_change) as u128
    } else if base_fee > base_fee_change {
        (base_fee - base_fee_change) as u128
    } else {
        0
    }
}

fn gwei_to_cents(value: U256) -> U256 {
    value * U256::from(ETH_TO_DOLLARS_RATIO * 100u128) / U256::from(1 * G * GWEI)
}

fn format_cents(estimation_in_cents: U256) -> String {
    if estimation_in_cents < 1 {
        return "< 0.01 $".to_string();
    }
    let decimal_value = estimation_in_cents % U256::from(100u128);
    let mut decimal_part = "".to_string();
    if decimal_value < 10 {
        decimal_part.push('0');
    }
    decimal_part.push_str(&decimal_value.to_string());
    let estimation_in_dollars = estimation_in_cents / U256::from(100u128);
    format!("{}.{} $", estimation_in_dollars, decimal_part)
}

fn read_line() -> String {
    let mut resp: String = String::new();
    std::io::stdin() // Get the standard input stream
        .read_line(&mut resp)
        .expect("Should have read Stdin");
    resp
}

fn confirm(prompt: &str) -> bool {
    println!("{} (Y/n)", prompt);
    loop {
        let resp = read_line();
        match resp.trim().to_lowercase().as_str() {
            "y" | "yes" => {
                return true;
            }
            "n" | "no" => {
                return false;
            }
            _ => {
                println!(
                    "Invalid input \"{}\", expect \"y\", \"yes\", \"n\" or \"no\" (not case sensitive).\n{} (Y/n)",
                    resp.trim(),
                    prompt
                );
            }
        }
    }
}

fn format_value_estimation(value: U256) -> String {
    let mut formatted_value = "".to_string();
    if value < 1 * GWEI {
        formatted_value.push_str(format!("{} wei", value).as_str());
    } else {
        let decimal_value = value % (U256::from(1 * GWEI));
        let mut decimal_part = "".to_string();
        if decimal_value > 0 {
            let mut acc = decimal_value.clone() * U256::from(10u128);
            while acc < 1 * GWEI {
                decimal_part.push('0');
                acc *= U256::from(10u128)
            }
            decimal_part.push_str(&decimal_value.to_string());
        } else {
            decimal_part.push('0');
        }
        formatted_value
            .push_str(format!("{}.{} gwei", value / (U256::from(1 * GWEI)), decimal_part).as_str());
    }
    let estimation_in_cents = gwei_to_cents(value);
    formatted_value.push_str(
        format!(
            " => ~ {} (assuming {})",
            format_cents(estimation_in_cents),
            ETH_TO_DOLLARS_RATIO_DESCRIPTION,
        )
        .as_str(),
    );
    formatted_value
}

fn format_transaction_summary(tx: TransactionRequest, estimated_fee: u128) -> String {
    let mut summary = format!(
        "from : {}\n",
        tx.from.expect("Should retreive transaction sender")
    );
    summary.push_str(
        format!(
            "to   : {}\n",
            tx.to
                .expect("Should retreive transaction receiver wrapper")
                .to()
                .expect("Should retreive transaction receiver")
        )
        .as_str(),
    );
    summary.push_str(
        format!(
            "nonce : {}\n",
            tx.nonce.expect("Should retreive transaction nonce")
        )
        .as_str(),
    );
    let value = U256::from(tx.value.expect("Should retreive transaction value"));

    summary.push_str(
        format!(
            "estimated fees : {}\n",
            format_value_estimation(U256::from(estimated_fee))
        )
        .as_str(),
    );
    summary.push_str(format!("value to transfer : {}\n", format_value_estimation(value)).as_str());
    let total = value + U256::from(estimated_fee);
    summary.push_str(format!("total debited : {}", format_value_estimation(total)).as_str());

    summary
}

async fn exec_transaction(
    sender_private_key: &[u8],
    sender: Address,
    recipient: Address,
    value: U256,
    node_url: Url,
) -> Result<TransactionReceipt<ReceiptEnvelope<Log<LogData>>>, PendingTransactionError> {
    println!("Building transaction");

    let signer = PrivateKeySigner::from_slice(sender_private_key)
        .expect("should have generated signer from private key bytes");
    let signer_address = signer.address();

    let provider = ProviderBuilder::new()
        .wallet(signer)
        .connect_http(node_url.clone());
    println!("Successfully connected to the node at {}", node_url);

    let nonce = provider
        .get_transaction_count(signer_address)
        .pending()
        .await
        .expect("should get nonce");

    let latest_block = provider
        .get_block(BlockId::latest())
        .await?
        .expect("Should have retreived the latest block from the node");

    let base_fee = calculate_base_fee_per_gas(
        latest_block.header.base_fee_per_gas.unwrap(),
        latest_block.header.gas_used,
        latest_block.header.gas_limit,
    );

    let tx_base = TransactionRequest::default().with_nonce(nonce);

    // Estimate gas for the deployment transaction
    let estimated_gas = provider.estimate_gas(tx_base.clone()).await?;

    let provider_gas_price = provider.get_gas_price().await?;
    println!("provider gas price : {:?} wei/gas", provider_gas_price);

    println!("estimated gas : {} gas", estimated_gas);

    let tip = base_fee / 5u128;

    let tx = tx_base
        .with_from(sender)
        .with_to(recipient)
        .with_nonce(nonce)
        .with_value(value)
        .with_gas_limit(estimated_gas)
        .with_max_priority_fee_per_gas(tip)
        .with_max_fee_per_gas(base_fee + tip);

    let estimated_fee = (base_fee + tip) * (estimated_gas as u128);

    let summary = format_transaction_summary(tx.clone(), estimated_fee);

    let transaction_approved = confirm(
        format!(
            "\ntransaction details : \n\n{}\n\nAre you sure you want to approve this transaction ?",
            summary
        )
        .as_str(),
    );

    if !transaction_approved {
        println!("Abort transaction");
        return Err(PendingTransactionError::FailedToRegister);
    }

    // Send deployment transaction
    let tx_builder = provider.send_transaction(tx).await?;
    println!("Transaction sent ({:#x}).", tx_builder.tx_hash());

    // 3 is ok for low amount transactions from what I understand
    let mut confirmations = 3u64;

    // arbitrary confirmations values I made up
    let mut secure_threshold = 10_000u128 * GWEI; // ~ 2cent at the time of writting
    while value > secure_threshold {
        secure_threshold *= 10u128;
        confirmations += 1u64;
    }

    // The way I understood confirmations, 1 confirmation = 1 block.
    // And it seems that 1 block ~ 10-15s.
    // Not really sure about any of that though.
    if confirmations < 5 {
        println!(
            "Waiting for {} confirmations ... (it should take less than minute)",
            confirmations
        );
    } else if confirmations < 9 {
        println!(
            "Waiting for {} confirmations ... (it should take about a minute or two)",
            confirmations
        );
    } else {
        println!(
            "Waiting for {} confirmations ... (it should take a few minutes)",
            confirmations
        );
    }

    tx_builder
        .with_required_confirmations(confirmations)
        .get_receipt()
        .await
}

#[tokio::main]
async fn main() {
    let private_key_bytes = get_private_key();
    let public_address_bytes = compute_public_address_from_private_key(&private_key_bytes);
    println!(
        "corresponding ETH Public address : \n0x{}\n",
        hex::encode(&public_address_bytes).to_uppercase()
    );

    let receiver_address_bytes = get_public_address();

    println!(
        "ETH Public address of the receiver : \n0x{}\n",
        hex::encode(&receiver_address_bytes).to_uppercase()
    );

    println!("Enter the amount to transfer in gwei:");
    let raw_value: String = read_line();
    let parsed_value = U256::from_str_radix(raw_value.trim(), 10);
    if parsed_value.is_err() {
        println!("Error : {}", parsed_value.unwrap_err());
        return;
    }
    let value = parsed_value.expect("Should parse value");
    println!("value to transfer : {} gwei\n", value);

    // // nodes I tested
    // let mut url_string = "https://ethereum-rpc.publicnode.com";
    // let mut url_string = "https://eth.merkle.io";
    let mut url_string = "https://eth.drpc.org";
    println!("url of the node to use : (default: {})", url_string);
    let raw_url: String = read_line();
    if raw_url.trim().len() > 0 {
        url_string = raw_url.trim();
    }
    println!("using node at {}\n", url_string);

    let receipt_result = exec_transaction(
        &private_key_bytes,
        public_address_bytes.into(),
        receiver_address_bytes.into(),
        value * U256::from(1 * GWEI),
        Url::parse(url_string).expect("Should have extracted the node url"),
    )
    .await;

    if let Ok(receipt) = receipt_result {
        if receipt.status() {
            println!(
                "Transaction ({:#x}) included in block {} ",
                receipt.transaction_hash,
                receipt.block_number.expect("Failed to get block number"),
            );
        } else {
            println!(
                "/!\\ TRANSACTION REVERTED /!\\\n block : {}",
                receipt.block_number.expect("Failed to get block number"),
            );
        }
    } else {
        println!(
            "/!\\ TRANSACTION FAILED /!\\\nerror : {}",
            receipt_result.unwrap_err(),
        );
    }
}
