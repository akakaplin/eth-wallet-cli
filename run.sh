#!/bin/bash

# Run Ethereum Wallet CLI with Etherscan API key

echo "🚀 Launching Ethereum Wallet CLI..."

# Run with cargo and set Etherscan API key
ETHERSCAN_API_KEY=2XBIT5RJ9ZTF1Z4W3VK2D63KDYXQUTRU4D cargo run -- "$@"