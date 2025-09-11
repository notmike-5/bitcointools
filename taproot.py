from bitcointools.hashes import tagged_hash
from bitcointools.helpers import bytes_to_hex, hex_to_bytes, get_compact_size, get_tests
import secp256k1

# secp256k1 curve order (for negation: -1 ≡ order - 1 mod order)
CURVE_ORDER = int('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16)

def negate_pubkey(pubkey: secp256k1.PublicKey) -> secp256k1.PublicKey:
    '''Negate a pubkey point (multiply by -1 on the curve)'''
    neg_scalar = (CURVE_ORDER - 1).to_bytes(32, 'big')  # -1 mod order
    return pubkey.tweak_mul(neg_scalar)

def tapleaf_hash(tapscript_ver: str = 'c0', script: str = None) -> str:
    '''Hash function for tapleaf'''
    if not script:
        print("Wat? You forgot the tap script.")
        return None
    script_bytes = hex_to_bytes(script)
    compact_size = get_compact_size(len(script_bytes))
    data_hex = tapscript_ver + compact_size + script
    data_bytes = hex_to_bytes(data_hex)
    return tagged_hash("TapLeaf", data_bytes).hex()

def tapbranch_hash(left, right):
    if left < right:
        return tagged_hash("TapBranch", hex_to_bytes(left) + hex_to_bytes(right))
    return tagged_hash("TapBranch", hex_to_bytes(right) + hex_to_bytes(left))

def collect_leaf_hashes(tree, hashes=None, debug=False):
    """Recursively collect leaf hashes in order (for verification)."""
    if hashes is None:
        hashes = []

    if isinstance(tree, dict):    # Leaf
        version = f"{tree['leafVersion']:x}"
        script = tree['script']
        h = tapleaf_hash(tapscript_ver=version, script=script)
        hashes.append(h)
        if debug:
            print(f"{script} => {h}")
    elif isinstance(tree, list):  # Branch: recurse on children
        for sub in tree:
            collect_leaf_hashes(sub, hashes, debug)
    else:
        raise ValueError("Invalid tree node")

    return hashes

def compute_merkle_root(tree):
    """Recursively compute taptree merkle root"""
    if isinstance(tree, dict):    # Leaf
        version = f"{tree['leafVersion']:x}"
        script = tree['script']
        return tapleaf_hash(tapscript_ver=version, script=script)

    elif isinstance(tree, list):  # Branch
        sub_roots = [compute_merkle_root(sub) for sub in tree]
        root = sub_roots[0]
        for h in sub_roots[1:]:
            root = tapbranch_hash(root, h)
        return root.hex()

    else:                         # badbadnotgood
        raise ValueError("Invalid tree node")

def compute_taproot_output(internal_pubkey, merkle_root):
    '''Compute the Taproot pubkey and scriptPubKey'''
    if len(internal_pubkey) != 32:
        print(f"internal_pubkey was {internal_pubkey}")
        raise ValueError("Internal pubkey must be 32 bytes")
    if len(merkle_root) != 32:
        print(f"merkle root was {merkle_root}")
        raise ValueError("Merkle root must be 32 bytes")

    # compute the tweak
    tweak = tagged_hash("TapTweak", internal_pubkey + merkle_root)

    # tweak the pubkey
    pubkey = secp256k1.PublicKey(b'\x02' + internal_pubkey, raw=True)
    tweaked_pubkey = pubkey.tweak_add(tweak)

    # ensure even y-coordinate
    serialized = tweaked_pubkey.serialize()
    if serialized[0] == 0x03:  # odd y
        tweaked_pubkey = negate_pubkey(tweaked_pubkey)
        serialized = tweaked_pubkey.serialize()

    # extract x-only (32-bytes, dropped 0x02 prefix)
    xonly_tweaked_pubkey = serialized[1:]

    script_pubkey = b"\x51\x20" + xonly_tweaked_pubkey

    return tweak.hex(), xonly_tweaked_pubkey.hex(), script_pubkey.hex()

# TODO: test coverage on create_taproot_mast
def create_taproot_mast(internal_pubkey_hex, script_tree):
    '''Create a Taproot MAST from scripts and internal pubkey'''
    try:
        internal_pubkey = hex_to_bytes(internal_pubkey_hex)
        taptree_root = hex_to_bytes(compute_merkle_root(script_tree))
        tweak, tweaked_pubkey, script_pubkey = compute_taproot_output(internal_pubkey, taptree_root)
        return {
            "taptree_root": taptree_root.hex(),
            "tweaked_pubkey": tweaked_pubkey,
            "script_pubkey": script_pubkey
        }
    except Exception as e:
        raise ValueError(f"Error creating Taproot MAST: {str(e)}") from e

def BIP341_tests():
    print("\nRunning Taproot (BIP-0341) Tests...")

    V = get_tests("bitcointools/test/bip341_wallet_test_vectors.json")

    #
    # BIP-341 - scriptPubKey Test Vectors
    #

    i=1
    for v in V['scriptPubKey']:
        print(f"\nBIP-341 Test Vector {i}\n", "-" * 25)
        i += 1

        # Extract the test data
        given, intermediary, expected = v['given'], v['intermediary'], v['expected']

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

        # Generate taptree

        # Case 1: Null taptree
        if script_tree is None:
            assert merkle_root is None
            assert script_pubkey == f"5120{tweaked_pubkey}"
            print("Null Script Tree")
            print(f"Merkle Root: {merkle_root}")
            print(f"scriptPubkey: {script_pubkey}")
            continue

        # Case 2: Single- and Multi-Leaf taptrees
        derived_hashes = collect_leaf_hashes(script_tree, debug=False)
        assert derived_hashes == leaf_hashes
        print(f"Leaf Hashes: {leaf_hashes}")

        derived_merkle_root = compute_merkle_root(script_tree)
        assert derived_merkle_root == merkle_root
        print(f"Merkle Root: {merkle_root}")

        # Generate tweak, tweakedPubKey, and scriptPubkey

        internal_pubkey_bytes, merkle_root_bytes = hex_to_bytes(internal_pubkey), hex_to_bytes(merkle_root)
        derived_tweak, derived_tweaked_pubkey, derived_script_pubkey = compute_taproot_output(internal_pubkey_bytes, merkle_root_bytes)

        assert derived_tweak == tweak
        assert derived_tweaked_pubkey == tweaked_pubkey
        assert derived_script_pubkey == script_pubkey

        print(f"Tweak is {tweak}")
        print(f"TweakedPubkey: {tweaked_pubkey}")
        print(f"ScriptPubkey: {script_pubkey}")

        # TODO: address encoding (covered in bech32.py, but move/re-create here)
        # TODO: verify scriptPathControlBlocks in scriptPubKey

    #
    # BIP-341 - keyPathSpending Test Vectors
    #

    print("\nAll BIP-341 Tests Passed Successfully!")

def BIP360_tests():
    print("\nRunning Taproot (BIP-0360) Tests...")

    V = get_tests("bitcointools/test/p2tsh_construction.json")

    #
    # BIP-360 - Test Vectors
    #

    i=1
    for v in V['test_vectors']:
        print(f"\nBIP-360 Test Vector {i}\n", "-" * 25)
        i += 1

        # Extract the test data
        id = v['id']
        objective = v['objective']


        # Given
        script_tree = v['given']['scriptTree']


        # Intermediary
        try:
            leaf_hashes = v['intermediary']['leafHashes']
        except:
            pass

        try:
            merkle_root = v['intermediary']['merkleRoot']
        except:
            merkle_root = None


        # Expected
        try:
            script_pubkey = v['expected']['scriptPubKey']
        except:
            script_pubkey = None

        try:
            bip350_address = v['expected']['bip350Address']
        except:
            pass

        try:
            script_path_control_blocks = v['expected']['scriptPathControlBlocks']
        except:
            pass

        try:
            error = v['expected']['error']
        except:
            pass


        # Generate taptree

        # Case 1: Null taptree
        if script_tree is None:
            assert merkle_root is None
            assert leaf_hashes == []
            assert script_pubkey is None
            print("Null Script Tree")
            print("Error: P2TSH requires a script tree with at least one leaf")
            continue

        # Case 2: Single- and Multi-Leaf taptrees
        derived_hashes = collect_leaf_hashes(script_tree, debug=False)
        assert derived_hashes == leaf_hashes
        print(f"Leaf Hashes: {leaf_hashes}")

        derived_merkle_root = compute_merkle_root(script_tree)
        assert derived_merkle_root == merkle_root
        print(f"Merkle Root: {merkle_root}")

        assert script_pubkey == f"5220{merkle_root}"
        print(f"ScriptPubkey: {script_pubkey}")

        print(f"\nPassed '{id}' with objective '{objective}'")

        # TODO verification of scriptPathControlBlocks in test_vectors

    print("\nAll BIP-360 Tests Passed Successfully!")

def run_tests():
    BIP341_tests()
    BIP360_tests()

if __name__ == '__main__':
    run_tests()
