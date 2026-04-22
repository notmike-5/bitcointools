"""simple example of a pay-to-taproot (p2tr) transaction"""

# from bitcointools.rpc import make_rpc_call
# from bitcointools.schnorr import pubkey_gen, schnorr_sign
from bitcointools.hashes import sha256
from bitcointools.bech32 import get_bech32_address
from bitcointools.taproot import create_taproot_mast
from bitcointools.transaction import OutPoint, TxIn, TxOut, Transaction
from bitcointools.sign import SigningContext
import json
import requests

#
# Create a P2TSH UTXO
#

# create a simple, one-leaf tree
script_tree = {
    "id": 0,
    "script": "206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac",
    "asm": "6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0 OP_CHECKSIG",
    "leafVersion": 192,
}

# generate a regtest address
address = get_bech32_address(script_tree["script"], witness_version=2, hrp="tb")

# get some coin

# Option 1: use the faucet @ api.bip360.org
data = {"user_addr": address}

resp = requests.post(url="http://api.bip360.org/faucet", data=data)
if not resp.status_code == 200:
    raise Exception("Failed to get a good txid.")
txid = resp.text

# Option 2: mine a block with regtest
# subprocess.run(['bitcoin-cli', ’-regtest’, '-named', 'generatetoaddress', address])


#
# Spend the P2TSH UTXO
#
