from hashes import tagged_hash
from helpers import bytes_to_hex, hex_to_bytes

def tapleaf_hash(script: str, tapscript_ver: hex = '0xc0'):
    '''Hash a TapScript'''

    return tagged_hash("TapLeaf", hex_to_bytes(tapscript_ver + + script))

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

def create_taproot_mast(scripts, internal_pubkey_hex):
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
