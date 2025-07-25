from hashes import hash256
from rpc import make_rpc_call
from helpers import parse_varint, reverse_bytes
from segwit import sanitize_segwit
from pprint import pprint

def get_block(blockhash, verbosity=1):
    return make_rpc_call("getblock", [blockhash, verbosity])

def getrawtransaction(txid: str, verbosity=1, blockhash=None):
    "Pull transaction from blockchain (default: localhost)"
    return make_rpc_call("getrawtransaction", [txid, verbosity])

def decoderawtransaction(hex: str, is_witness=False):
    "Decode a transaction or witness from hex"
    return make_rpc_call("decoderawtransaction", [hex, is_witness])

def get_txid(serialized_tx):
    if serialized_tx[8:12] == '0001':  # segwit
        serialized_tx = sanitize_segwit(serialized_tx)
    hash = hash256(bytes.fromhex(serialized_tx)).hex()
    return reverse_bytes(hash)

tx_keys = ['txid', 'hash', 'version', 'size', 'vsize', 'weight', 'locktime', 'vin', 'vout', 'hex', 'blockhash', 'confirmations', 'time', 'blocktime']

genesis = get_block("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", 3)
plus_one = get_block("00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048", 3)

pprint(get_block("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"))



# filter on type(witness_v1_taproot) and is_spent(true)

# { 'txhash': "",
#     'desc': "" }

p2tr_txs = [ { 'txid': "33e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac98799036",
               'desc': "first P2TR"},

             { 'txid': "37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8",
               'desc': "First TX with both a P2TR script-path and a P2TR key-path input"},

             { 'txid': "83c8e0289fecf93b5a284705396f5a652d9886cbd26236b0d647655ad8a37d82",
               'desc': "First multiple P2TR key-path inputs"},

             { 'txid': "905ecdf95a84804b192f4dc221cfed4d77959b81ed66013a7e41a6e61e7ed530",
               'desc': "First script-path 2-of-2 multisig spend" },

             { 'txid': "2eb8dbaa346d4be4e82fe444c2f0be00654d8cfd8c4a9a61b11aeaab8c00b272",
               'desc': "First use of OP_CHECKSIGADD" } ]

for t in p2tr_txs:
    t['raw'] = getrawtransaction(t['txid'], False)
    t['unpacked'] = getrawtransaction(t['txid'])

p2tr_txs[3]['parent'] = getrawtransaction("5b79f5d6039c188613342eb13961dd7d1e1a0f90023d3eaed25fc85a29201bb4")

pprint(p2tr_txs[3]['raw'])

print(list(p2tr_txs[3]['unpacked'].keys()))

pprint(p2tr_txs[3]['unpacked'])

pprint(p2tr_txs[3]['unpacked']['vin'])

txinwitness = p2tr_txs[3]['unpacked']['vin'][0]['txinwitness']

scriptPubKey = p2tr_txs[3]['unpacked']['vout'][0]['scriptPubKey']
value = p2tr_txs[3]['unpacked']['vout'][0]['value']

pprint(p2tr_txs[3]['unpacked']['vout'])

out_3 = getrawtransaction("80975cddebaa93aa21a6477c0d050685d6820fa1068a2731db0f39b535cbd369")['vin'][3]
witness = getrawtransaction("80975cddebaa93aa21a6477c0d050685d6820fa1068a2731db0f39b535cbd369")['vin'][3]['txinwitness']

pprint(out_3)
