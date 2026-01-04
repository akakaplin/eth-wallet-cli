use clap::{Parser, Subcommand};
use ethers::prelude::*;
use ethers::utils::format_units;
use serde::Deserialize;
use tabled::{Table, Tabled, settings::Style};
use dotenv::dotenv;
use std::convert::TryFrom;
use rand::Rng;

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
    #[tabled(rename = "From/To")]
    counterparty: String,
    #[tabled(rename = "Value (ETH)")]
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
    message: String,
    result: Vec<EtherscanTransaction>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();
    
    let cli = Cli::parse();
    let provider = Provider::<Http>::try_from("https://ethereum.publicnode.com")?;
    
    match cli.command {
        Some(Commands::List) => list_wallets()?,
        Some(Commands::Balance { address }) => {
            if let Some(addr) = address {
                let wallet_address = addr.parse::<Address>()?;
                print_balance(provider.clone(), wallet_address, Some(wallet_address)).await?;
            } else {
                for wallet in get_wallets()? {
                    print_balance(provider.clone(), wallet, None).await?;
                }
            }
        }
        Some(Commands::Tx { address }) => {
            if let Some(addr) = address {
                let wallet_address = addr.parse::<Address>()?;
                print_transactions(provider.clone(), wallet_address, Some(wallet_address)).await?;
            } else {
                for wallet in get_wallets()? {
                    print_transactions(provider.clone(), wallet, None).await?;
                }
            }
        }
        Some(Commands::Generate { count }) => {
            generate_keys(count)?;
        }
        None => list_wallets()?,
    }
    
    Ok(())
}

async fn print_balance(provider: Provider<Http>, wallet_address: Address, title_address: Option<Address>) -> Result<(), Box<dyn std::error::Error>> {
    let title_wallet = title_address.unwrap_or(wallet_address);
    println!("🔍 Wallet: {:#x}\n", title_wallet);
    
    let eth_balance = provider.get_balance(wallet_address, None).await?;
    let eth_balance_eth = format_units(eth_balance, "ether")?;
    
    let balances = vec![
        BalanceRow {
            token: "ETH".to_string(),
            balance: format!("{:.6}", eth_balance_eth),
            usd_value: "~".to_string(),
        },
        BalanceRow {
            token: "WETH".to_string(),
            balance: "0.000000".to_string(),
            usd_value: "~".to_string(),
        },
        BalanceRow {
            token: "USDT".to_string(),
            balance: "0.00".to_string(),
            usd_value: "~".to_string(),
        },
    ];
    
    println!("{}", Table::new(&balances).with(Style::modern()));
    println!();
    
    Ok(())
}

async fn print_transactions(provider: Provider<Http>, wallet_address: Address, title_address: Option<Address>) -> Result<(), Box<dyn std::error::Error>> {
    let title_wallet = title_address.unwrap_or(wallet_address);
    println!("🔍 Wallet: {:#x}\n", title_wallet);
    println!("📊 Recent Transactions (last 100):");
    
    let transactions = get_transactions(provider.clone(), wallet_address, 100).await?;
    
    if transactions.is_empty() {
        println!("No transactions found for this wallet.");
    } else {
        println!("{}", Table::new(&transactions).with(Style::modern()));
    }
    println!();
    
    Ok(())
}

fn list_wallets() -> Result<(), Box<dyn std::error::Error>> {
    let wallets_str = std::env::var("WALLETS").unwrap_or_else(|_| "".to_string());
    
    if wallets_str.is_empty() {
        println!("❌ No wallets found in .env file");
        println!("Add wallets to .env file like:");
        println!("WALLETS=0x1234...,0x5678...");
        return Ok(());
    }
    
    println!("📋 Wallets from .env file:\n");
    for (i, wallet_str) in wallets_str.split(',').enumerate() {
        let wallet_str = wallet_str.trim();
        match wallet_str.parse::<Address>() {
            Ok(address) => {
                println!("{}. {:#x}", i + 1, address);
            }
            Err(_) => {
                println!("{}. ❌ Invalid address: {}", i + 1, wallet_str);
            }
        }
    }
    
    println!();
    Ok(())
}

fn get_wallets() -> Result<Vec<Address>, Box<dyn std::error::Error>> {
    let wallets_str = std::env::var("WALLETS").unwrap_or_else(|_| "".to_string());
    
    if wallets_str.is_empty() {
        return Err("No wallets found in WALLETS environment variable".into());
    }
    
    wallets_str
        .split(',')
        .map(|s| s.trim().parse::<Address>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("Failed to parse wallet addresses: {}", e).into())
}

async fn get_transactions(_provider: Provider<Http>, wallet_address: Address, limit: usize) -> Result<Vec<TransactionRow>, Box<dyn std::error::Error>> {
    println!("Fetching transactions from Etherscan API...");
    
    let wallet_str = format!("{:#x}", wallet_address);
    let api_key = std::env::var("ETHERSCAN_API_KEY").unwrap_or_else(|_| "YourApiKeyToken".to_string());
    let url = format!(
        "https://api.etherscan.io/v2/api?chainid=1&module=account&action=txlist&address={}&sort=desc&apikey={}&limit={}",
        wallet_str, api_key, limit
    );
    
    let response = reqwest::get(&url).await?;
    let etherscan_data: EtherscanResponse = response.json().await?;
    
    if etherscan_data.status != "1" {
        return Err(format!("Etherscan API error: {}", etherscan_data.message).into());
    }
    
    let provider = Provider::<Http>::try_from("https://ethereum.publicnode.com")?;
    let current_balance = provider.get_balance(wallet_address, None).await?;
    let mut running_balance = current_balance;
    
    let mut transactions = Vec::new();
    for tx in etherscan_data.result.into_iter().take(limit) {
        let value_u256 = U256::from_str_radix(&tx.value, 16)?;
        let value_eth = format_units(value_u256, "ether")?;
        
        let (tx_type, counterparty) = if tx.from.to_lowercase() == wallet_str.to_lowercase() {
            running_balance = running_balance.saturating_add(value_u256);
            running_balance = running_balance.saturating_sub(value_u256);
            let to_addr = tx.to.unwrap_or_else(|| "Contract".to_string());
            let to_end = if to_addr.len() > 10 { 10 } else { to_addr.len() };
            let to_short = format!("> 0x{}...", &to_addr[2..to_end]);
            ("OUT".to_string(), to_short)
        } else {
            running_balance = running_balance.saturating_add(value_u256);
            let from_end = if tx.from.len() > 10 { 10 } else { tx.from.len() };
            let from_short = format!("< 0x{}...", &tx.from[2..from_end]);
            ("IN".to_string(), from_short)
        };
        
        let hash_end = if tx.hash.len() > 10 { 10 } else { tx.hash.len() };
        let hash_short = format!("0x{}...", &tx.hash[2..hash_end]);
        
        transactions.push(TransactionRow {
            tx_type,
            hash: hash_short,
            counterparty,
            value: format!("{:.6}", value_eth),
            balance_after: format!("{:.6}", format_units(running_balance, "ether")?),
            timestamp: tx.timestamp,
        });
    }
    
    Ok(transactions)
}

fn generate_keys(count: usize) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔑 Generating {} Ethereum key pair(s)...\n", count);
    
    let mut rng = rand::thread_rng();
    
    for i in 1..=count {
        // Generate random private key (32 bytes)
        let mut private_key_bytes = [0u8; 32];
        rng.fill(&mut private_key_bytes);
        
        // Create private key and address
        let private_key = LocalWallet::from_bytes(&private_key_bytes)?;
        let address = private_key.address();
        
        let private_key_hex = format!("{:#x}", private_key.signer().to_bytes());
        let address_hex = format!("{:#x}", address);
        
        println!("┌─────────────────────────────────────────────────────────────┐");
        println!("│                     🔐 Key Pair #{}                    │", i);
        println!("├─────────────────────────────────────────────────────────────┤");
        println!("│ 🔑 Private Key:                                      │");
        println!("│   {}│", private_key_hex);
        println!("│                                                     │");
        println!("│ 📍 Address:                                         │");
        println!("│   {}│", address_hex);
        println!("└─────────────────────────────────────────────────────────────┘");
        println!();
    }
    
    println!("⚠️  IMPORTANT: Keep your private keys secure and never share them!");
    println!("    Store them safely and only use private keys you trust.");
    Ok(())
}