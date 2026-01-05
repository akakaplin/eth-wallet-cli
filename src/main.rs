use clap::{Parser, Subcommand};
use dotenv::dotenv;
use ethers::prelude::*;
use ethers::utils::format_units;
use rand::Rng;
use serde::Deserialize;
use tabled::{Table, Tabled, settings::Style};

const WETH_ADDRESS: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
const USDT_ADDRESS: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
const BALANCE_OF_SELECTOR: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

#[derive(Parser)]
#[command(name = "eth-wallet-cli")]
#[command(about = "A minimalistic Ethereum wallet CLI")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    List,
    Balance {
        #[arg(short, long)]
        address: Option<String>,
    },
    Tx {
        #[arg(short, long)]
        address: Option<String>,
    },
    Generate {
        #[arg(short, long, default_value = "1")]
        count: usize,
    },
}

#[derive(Tabled)]
struct BalanceRow {
    #[tabled(rename = "Token")]
    token: String,
    #[tabled(rename = "Balance")]
    balance: String,
    #[tabled(rename = "USD Value")]
    usd_value: String,
}

#[derive(Tabled)]
struct TransactionRow {
    #[tabled(rename = "Type")]
    tx_type: String,
    #[tabled(rename = "Hash")]
    hash: String,
    #[tabled(rename = "Token")]
    token: String,
    #[tabled(rename = "From/To")]
    counterparty: String,
    #[tabled(rename = "Value")]
    value: String,
    #[tabled(rename = "Balance After")]
    balance_after: String,
    #[tabled(rename = "Timestamp")]
    timestamp: String,
}

#[derive(Deserialize)]
struct EtherscanTransaction {
    hash: String,
    from: String,
    to: Option<String>,
    value: String,
    #[serde(rename = "timeStamp")]
    timestamp: String,
}

#[derive(Deserialize)]
struct EtherscanResponse {
    status: String,
    result: Vec<EtherscanTransaction>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    let cli = Cli::parse();
    let provider = Provider::<Http>::try_from("https://ethereum.publicnode.com")?;

    match cli.command {
        Some(Commands::List) => list_wallets(),
        Some(Commands::Balance { address }) => handle_balance(provider, address).await,
        Some(Commands::Tx { address }) => handle_transactions(provider, address).await,
        Some(Commands::Generate { count }) => generate_keys(count),
        None => list_wallets(),
    }
}

async fn handle_balance(
    provider: Provider<Http>,
    address: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(addr) = address {
        let wallet = addr.parse::<Address>()?;
        print_balance(provider, wallet, Some(wallet)).await?;
    } else {
        for wallet in get_wallets()? {
            print_balance(provider.clone(), wallet, None).await?;
        }
    }
    Ok(())
}

async fn handle_transactions(
    provider: Provider<Http>,
    address: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(addr) = address {
        let wallet = addr.parse::<Address>()?;
        print_transactions(provider, wallet, Some(wallet)).await?;
    } else {
        for wallet in get_wallets()? {
            print_transactions(provider.clone(), wallet, None).await?;
        }
    }
    Ok(())
}

async fn get_token_balance(
    provider: &Provider<Http>,
    wallet: Address,
    token_addr: &str,
    decimals: u32,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut call_data = BALANCE_OF_SELECTOR.to_vec();
    call_data.extend_from_slice(&[0u8; 12]);
    call_data.extend_from_slice(wallet.as_bytes());

    let tx = Eip1559TransactionRequest::new()
        .to(token_addr.parse::<Address>()?)
        .data(call_data)
        .into();

    let balance_bytes = provider.call(&tx, None).await?;
    let balance = U256::from_big_endian(&balance_bytes);
    Ok(format_units(balance, decimals)?)
}

async fn print_balance(
    provider: Provider<Http>,
    wallet: Address,
    title: Option<Address>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Wallet: {:#x}", title.unwrap_or(wallet));

    let eth_balance = format_units(provider.get_balance(wallet, None).await?, "ether")?;
    let weth_balance = get_token_balance(&provider, wallet, WETH_ADDRESS, 18u32).await?;
    let usdt_balance = get_token_balance(&provider, wallet, USDT_ADDRESS, 6u32).await?;

    let balances = vec![
        BalanceRow {
            token: "ETH".to_string(),
            balance: format!("{:.6}", eth_balance),
            usd_value: "~".to_string(),
        },
        BalanceRow {
            token: "WETH".to_string(),
            balance: format!("{:.6}", weth_balance),
            usd_value: "~".to_string(),
        },
        BalanceRow {
            token: "USDT".to_string(),
            balance: format!("{:.2}", usdt_balance.parse::<f64>().unwrap_or(0.0)),
            usd_value: "~".to_string(),
        },
    ];

    println!("{}\n", Table::new(&balances).with(Style::modern()));
    Ok(())
}

async fn print_transactions(
    provider: Provider<Http>,
    wallet: Address,
    title: Option<Address>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "🔍 Wallet: {:#x}\n📊 Recent Transactions (last 100):",
        title.unwrap_or(wallet)
    );

    match get_transactions(provider.clone(), wallet, 100).await {
        Ok(txs) if !txs.is_empty() => println!("{}", Table::new(&txs).with(Style::modern())),
        Ok(_) => println!("No transactions found for this wallet."),
        Err(e) if e.to_string().contains("No transactions") => {
            println!("No transactions found for this wallet.")
        }
        Err(e) => println!("Error fetching transactions: {}", e),
    }
    println!();
    Ok(())
}

fn list_wallets() -> Result<(), Box<dyn std::error::Error>> {
    let wallets_str = std::env::var("WALLETS").unwrap_or_default();

    if wallets_str.is_empty() {
        println!("❌ No wallets found in .env file\nAdd wallets like: WALLETS=0x1234...,0x5678...");
        return Ok(());
    }

    println!("📋 Wallets from .env file:\n");
    for (i, wallet_str) in wallets_str.split(',').enumerate() {
        match wallet_str.trim().parse::<Address>() {
            Ok(addr) => println!("{}. {:#x}", i + 1, addr),
            Err(_) => println!("{}. ❌ Invalid address: {}", i + 1, wallet_str.trim()),
        }
    }
    println!();
    Ok(())
}

fn get_wallets() -> Result<Vec<Address>, Box<dyn std::error::Error>> {
    let wallets_str = std::env::var("WALLETS").unwrap_or_default();
    if wallets_str.is_empty() {
        return Err("No wallets found".into());
    }
    wallets_str
        .split(',')
        .map(|s| s.trim().parse::<Address>())
        .collect::<Result<_, _>>()
        .map_err(|e| e.into())
}

#[derive(Deserialize)]
struct Erc20Transaction {
    hash: String,
    from: String,
    to: String,
    value: String,
    #[serde(rename = "tokenSymbol")]
    token_symbol: String,
    #[serde(rename = "tokenDecimal")]
    token_decimal: String,
    #[serde(rename = "timeStamp")]
    timestamp: String,
}

#[derive(Deserialize)]
struct Erc20Response {
    status: String,
    result: Vec<Erc20Transaction>,
}

async fn get_transactions(
    provider: Provider<Http>,
    wallet: Address,
    limit: usize,
) -> Result<Vec<TransactionRow>, Box<dyn std::error::Error>> {
    println!("Fetching transactions from Etherscan API...");

    let wallet_str = format!("{:#x}", wallet);
    let api_key =
        std::env::var("ETHERSCAN_API_KEY").unwrap_or_else(|_| "YourApiKeyToken".to_string());

    // Fetch regular ETH transactions
    let eth_url = format!(
        "https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address={}&sort=desc&apikey={}&limit={}",
        wallet_str, api_key, limit
    );
    let eth_response: EtherscanResponse = reqwest::get(&eth_url).await?.json().await?;

    // Fetch ERC-20 token transfers
    let erc20_url = format!(
        "https://api.etherscan.io/v2/api?chainid=1&module=account&action=tokentx&address={}&sort=desc&apikey={}&limit={}",
        wallet_str, api_key, limit
    );
    let erc20_response: Erc20Response = reqwest::get(&erc20_url).await?.json().await?;

    let mut running_balance = provider.get_balance(wallet, None).await?;
    let mut transactions = Vec::new();

    // Process ETH transactions
    if eth_response.status == "1" {
        for tx in eth_response.result.into_iter().take(limit) {
            let value = U256::from_str_radix(&tx.value, 16)?;
            let value_eth = format_units(value, "ether")?;

            let (tx_type, counterparty) = if tx.from.to_lowercase() == wallet_str.to_lowercase() {
                running_balance = running_balance.saturating_sub(value);
                let to_addr = tx.to.unwrap_or_else(|| "Contract".to_string());
                let to_short = format!("> 0x{}...", &to_addr[2..to_addr.len().min(10)]);
                ("OUT".to_string(), to_short)
            } else {
                running_balance = running_balance.saturating_add(value);
                let from_short = format!("< 0x{}...", &tx.from[2..tx.from.len().min(10)]);
                ("IN".to_string(), from_short)
            };

            let hash_short = format!("0x{}...", &tx.hash[2..tx.hash.len().min(10)]);

            transactions.push(TransactionRow {
                tx_type,
                hash: hash_short,
                token: "ETH".to_string(),
                counterparty,
                value: format!("{:.6}", value_eth),
                balance_after: format!("{:.6}", format_units(running_balance, "ether")?),
                timestamp: tx.timestamp,
            });
        }
    }

    // Process ERC-20 transactions (USDT and WETH only)
    if erc20_response.status == "1" {
        for tx in erc20_response
            .result
            .into_iter()
            .take(limit)
            .filter(|t| t.token_symbol == "USDT" || t.token_symbol == "WETH")
        {
            let value = U256::from_str_radix(&tx.value, 10)?;
            let decimals: u32 = tx.token_decimal.parse().unwrap_or(18);
            let value_formatted = format_units(value, decimals)?;

            let (tx_type, counterparty) = if tx.from.to_lowercase() == wallet_str.to_lowercase() {
                let to_short = format!("> 0x{}...", &tx.to[2..tx.to.len().min(10)]);
                ("OUT".to_string(), to_short)
            } else {
                let from_short = format!("< 0x{}...", &tx.from[2..tx.from.len().min(10)]);
                ("IN".to_string(), from_short)
            };

            let hash_short = format!("0x{}...", &tx.hash[2..tx.hash.len().min(10)]);
            let display_value = if tx.token_symbol == "USDT" {
                format!("{:.2}", value_formatted.parse::<f64>().unwrap_or(0.0))
            } else {
                format!("{:.6}", value_formatted)
            };

            transactions.push(TransactionRow {
                tx_type,
                hash: hash_short,
                token: tx.token_symbol,
                counterparty,
                value: display_value,
                balance_after: "~".to_string(),
                timestamp: tx.timestamp,
            });
        }
    }

    // Sort by timestamp (descending)
    transactions.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    // Take only the requested limit
    transactions.truncate(limit);

    Ok(transactions)
}

fn generate_keys(count: usize) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔑 Generating {} Ethereum key pair(s)...\n", count);
    let mut rng = rand::thread_rng();

    for i in 1..=count {
        let mut private_key_bytes = [0u8; 32];
        rng.fill(&mut private_key_bytes);

        let wallet = LocalWallet::from_bytes(&private_key_bytes)?;
        let private_key = format!("{:#x}", wallet.signer().to_bytes());
        let address = format!("{:#x}", wallet.address());

        const BOX_WIDTH: usize = 70;
        let title = format!(" Key Pair #{}", i);
        let title_padding = (BOX_WIDTH - title.len() - 2) / 2;

        println!("┌{}┐", "─".repeat(BOX_WIDTH));
        println!(
            "│{}{}{}│",
            " ".repeat(title_padding),
            title,
            " ".repeat(BOX_WIDTH - title_padding - title.len())
        );
        println!("├{}┤", "─".repeat(BOX_WIDTH));
        println!("│ Private Key: {}│", " ".repeat(BOX_WIDTH - 14));
        println!(
            "│   {}{}│",
            private_key,
            " ".repeat(BOX_WIDTH - 3 - private_key.len())
        );
        println!("│   {}│", " ".repeat(BOX_WIDTH - 3));
        println!("│ Address: {}│", " ".repeat(BOX_WIDTH - 10));
        println!(
            "│   {}{}│",
            address,
            " ".repeat(BOX_WIDTH - 3 - address.len())
        );
        println!("└{}┘\n", "─".repeat(BOX_WIDTH));
    }

    println!("⚠️  IMPORTANT: Keep your private keys secure and never share them!");
    Ok(())
}
