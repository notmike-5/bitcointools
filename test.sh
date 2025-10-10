#!/usr/bin/env bash

# run tests for all modules
mods=("address" "base58" "bech32" "hashes" "helpers" "schnorr" "segwit" "taproot" "transaction")

for m in "${mods[@]}"; do
    python -m "$m"
done
