from hashes import tagged_hash
from helpers import bytes_to_hex, hex_to_bytes
import json
from pprint import pprint

def tapleaf_hash(tapscript_ver: hex = '0xc0', script: str = None) -> bytes:
    '''Hash a TapScript'''
    if not script:
        print("Wat? You forgot the tap script.")
        return None
    return tagged_hash("TapLeaf", hex_to_bytes(tapscript_ver + script))

def build_taptree(leafhashes: list) -> int:
    '''Build Merkle tree from list of scripts and return root'''
    if not scripts:
        raise ValueError("Script list cannot be empty")

    leaves = []

    while len(leaves) > 1:
        tmp_leaves = []
        for i in range(0, len(leaves), 2):
            if i+1 >= len(leaves):
                leaves.append(leaves[-1])
            left, right = sorted([leaves[i], leaves[i+1]])
            parent = tagged_hash("TapBranch", left + right)
            tmp_leaves.append(parent)
        leaves = tmp_leaves

    return leaves[0]

def compute_taproot_output(internal_pubkey, merkle_root):
    '''Compute the Taproot pubkey and scriptPubKey'''
    if len(internal_pubkey) != 32:
        raise ValueError("Internal pubkey must be 32 bytes")
    if len(merkle_root) != 32:
        raise ValueError("Merkle root must be 32 bytes")

    tweak = tagged_hash("TapTweak", internal_pubkey + merkle_root)

    tweaked_pubkey = tweak
    script_pubkey = b"\x51\x20" + tweaked_pubkey

    return tweaked_pubkey, script_pubkey

def create_taproot_mast(internal_pubkey_hex, scripts):
    '''Create a Taproot MAST from scripts and internal pubkey'''
    try:
        internal_pubkey = hex_to_bytes(internal_pubkey_hex)
        merkle_root= merkelize_scripts(scripts)
        tweaked_pubkey, script_pubkey = compute_taproot_output(internal_pubkey, merkle_root)
        return {
            "merkle_root": bytes_to_hex(merkle_root),
            "tweaked_pubkey": bytes_to_hex(tweaked_pubkey),
            "script_pubkey": bytes_to_hex(script_pubkey)
        }
    except Exception as e:
        raise ValueError(f"Error creating Taproot MAST: {str(e)}") from e

def run_tests(test_vectors: str="test/BIP341_wallet_test_vectors.json"):
    with open(test_vectors, 'r') as f:

        vectors = json.load(f)

        # scriptPubKey Test Vectors
        i=1
        for v in vectors['scriptPubKey']:
            given = v['given']
            intermediary = v['intermediary']
            expected = v['expected']

            internal_pubkey = given['internalPubkey']
            script_tree = given['scriptTree']

            try:
                leaf_hashes = intermediary['leafHashes']
            except:
                pass

            merkle_root = intermediary['merkleRoot']
            tweak = intermediary['tweak']
            tweaked_pubkey = intermediary['tweakedPubkey']

            script_pubkey = expected['scriptPubKey']
            bip350_address = expected['bip350Address']
            try:
                script_path_control_blocks = expected['scriptPathControlBlocks']
            except:
                pass
            print(f"Test {i}")
            print("*******")
            pprint(f"Given: {given}")
            print()
            pprint(f"Intermediary: {intermediary}")
            print()
            pprint(f"Expected: {expected}")
            print()

            i += 1

if __name__ == '__main__':
    run_tests()
