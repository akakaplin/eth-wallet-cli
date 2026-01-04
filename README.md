# Ethereum Wallet CLI

A minimalistic Rust CLI for Ethereum wallet analysis and key generation.

## Quick Start

```bash
# List wallets from .env
eth-wallet-cli list

# Get balances
eth-wallet-cli balance
eth-wallet-cli balance --address 0x1234...

# Get transactions  
eth-wallet-cli tx
eth-wallet-cli tx --address 0x1234...

# Generate keys
eth-wallet-cli generate
eth-wallet-cli generate --count 3
```

### Dependencies
- `ethers` - Ethereum library
- `tokio` - Async runtime
- `tabled` - Table formatting
- `clap` - CLI parsing
- `serde` - Serialization
- `reqwest` - HTTP client
- `rand` - Cryptographic randomness

## Security

**Important Security Notes:**
- Never share private keys
- Store private keys securely
- Only use keys you generated yourself
- Etherscan API key is included - change if needed

## License

MIT License - see LICENSE file for details.
