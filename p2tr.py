"""simple example of a pay-to-taproot (p2tr) transaction"""

# from bitcointools.rpc import make_rpc_call
# from bitcointools.schnorr import pubkey_gen, schnorr_sign
from bitcointools.bech32 import get_bech32_address
from bitcointools.taproot import create_taproot_mast
from bitcointools.transaction import OutPoint, TxIn, TxOut, Transaction
from bitcointools.sign import SigningContext
import json
import requests

# These are some values that we take to be true at the outset. Their only use is to facilitate the
# testing of values that are produced by the ‘bitcointools‘ implementation.

# https://learnmeabitcoin.com/technical/upgrades/taproot/#example-3-script-path-spend-signature
truth = {
    "construct": {
        "internal_pubkey": "924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329",
        "leaf_version": "c0",
        "leaf_script": "206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac",
        "leaf_hash": "858dfe26a3dd48a2c1fcee1d631f0aadf6a61135fc51f75758e945bca534ef16",
        "taptree_root": "858dfe26a3dd48a2c1fcee1d631f0aadf6a61135fc51f75758e945bca534ef16",
        "tweak": "479785dd89a6441dbe00c7661865a0cc68672e8021f4547ac7f89ac26ac049f2",
        "tweaked_pubkey": "f3778defe5173a9bf7169575116224f961c03c725c0e98b8da8f15df29194b80",
        "script_pubkey": "5120f3778defe5173a9bf7169575116224f961c03c725c0e98b8da8f15df29194b80",
    },
    "spend": {
        "script private key": "9b8de5d7f20a8ebb026a82babac3aa47a008debbfde5348962b2c46520bd5189",
        "sighash": "752453d473e511a0da2097d664d69fe5eb89d8d9d00eab924b42fc0801a980c9",
        "aux_rand": "0000000000000000000000000000000000000000000000000000000000000000",
        "signature": (
            "01769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c770"
            "0615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f01"
        ),
        "leaf_script": "206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac",
        "control_byte": "c0",
        "public_key": "924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329",
        "merkle_path": "",
        "control_block": "c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329",
        "witness": (
            "034101769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c77"
            "00615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f0122"
            "206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac"
            "21c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329"
        ),
    },
}


#
# Create a P2TR UTXO
#

internal_pubkey = truth["construct"]["internal_pubkey"]

# create a simple, one-leaf tree
script_tree = {
    "id": 0,
    "script": "206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac",
    "asm": "6d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0 OP_CHECKSIG",
    "leafVersion": 192,
}

# create a taproot mast
mast = create_taproot_mast(internal_pubkey, script_tree)

taptree_root = mast["taptree_root"]
tweaked_pubkey = mast["tweaked_pubkey"]
script_pubkey = mast["script_pubkey"]

# sanity checks
assert taptree_root == truth["construct"]["taptree_root"]
assert tweaked_pubkey == truth["construct"]["tweaked_pubkey"]
assert script_pubkey == truth["construct"]["script_pubkey"]

# generate a regtest address
address = get_bech32_address(tweaked_pubkey, witness_version=1, hrp="tb")


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
# Spend the Taproot UTXO via a Script-path Spend
#

# Get the actual transaction details
data = {"txid": txid}
resp = requests.get(url="http://api.bip360.org/getrawtransaction", data=data)
txdata = json.loads(resp.text)

vout = amount = spk = None
for i, output in enumerate(txdata["vout"]):
    if output["scriptPubKey"]["address"] == address:
        vout = i
        amount = int(output["value"] * 100_000_000)  # satoshis
        spk = output["scriptPubKey"]["hex"]
        break
outpoint = OutPoint(txid=txid, vout=vout)
txout = TxOut(amount=amount, scriptPubkey=bytes.fromhex(spk))
utxo_set = {outpoint: txout}

# form the witness [signature, leaf_script, control block]
witness = [
    (
        "4101769105cbcbdcaaee5e58cd201ba3152477fda31410df8b91b4aee2c4864c77"
        "00615efb425e002f146a39ca0a4f2924566762d9213bd33f825fad83977fba7f01"
    ),
    "22206d4ddc0e47d2e8f82cbe2fc2d0d749e7bd3338112cecdc76d8f831ae6620dbe0ac",
    "21c0924c163b385af7093440184af6fd6244936d1288cbb41cc3812286d3f83a3329",
]

# provide inputs and outputs
vin = TxIn(prevout=outpoint, witness=witness)
vout = TxOut(
    amount=5000000,
    scriptPubkey="5120f3778defe5173a9bf7169575116224f961c03c725c0e98b8da8f15df29194b80",
)

# create the spending transaction
tx = Transaction(inputs=[vin], outputs=[vout])

# sign it
context = SigningContext(tx, utxo_set)
sighash, message = context.taproot_sighash(0, 0x1)
