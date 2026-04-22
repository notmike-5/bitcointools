"""
Testbed for Entropy Derivation Scheme
"""

from __future__ import annotations
import json
from bitcoinpqc import Algorithm, keygen
from bitcointools.bip32 import ser32, ser256, parse256
from bitcointools.bip39 import Mnemonic
from bitcointools.hashes import hmac_sha512
from bitcointools.schnorr import lift_x, has_even_y, pubkey_gen
from Crypto.Cipher import ChaCha20

HARDENED_OFFSET = 2**31


class SimpleHDNode:
    def __init__(self, entropy: int, chaincode: bytes, depth: int = 0, index: int = 0):
        """Initialize SimpleHDNode"""
        self._entropy = entropy
        self._chaincode = chaincode
        self.depth = depth
        self.index = index

    @property
    def chaincode(self) -> bytes:
        """Returns the chaincode for this node"""
        return self._chaincode

    @property
    def entropy(self) -> int:
        """Returns the entropy for this node"""
        return self._entropy

    def ced(self, index):
        """Returns child entropy given parent entropy and chaincode."""
        if not (0 <= index < 2**32):
            raise ValueError("Invalid child index")

        data = ser256(self._entropy) + ser32(index)

        I = hmac_sha512(self._chaincode, data)
        IL, IR = I[:32], I[32:]

        child_entropy = parse256(IL)
        child_chaincode = IR

        if self.depth == 255:
            raise ValueError("Max depth reached")
        else:
            return SimpleHDNode(child_entropy, child_chaincode, self.depth + 1, index)

    # Path Derivation

    def derive(self, path: str) -> SimpleHDNode:
        """
        Derive a descendant node from BIP32-style path string

        examples:
            node.derive("m/360'////")
        """
        if path == "m":
            return self

        # check for invalid derivation path
        if not path.startswith("m/"):
            raise ValueError("Invalid derivation path")

        node = self
        for p in path.split("/")[1:]:
            hardened = p.endswith("'")
            # catch non-integer path components
            try:
                index = int(p[:-1]) if hardened else int(p)
            except ValueError:  # for instance, "m/foo" was given
                raise ValueError(f"Invalid path component: '{p}'")

            # check for negative indices pre-shift
            if not (0 <= index < 2**31):
                raise ValueError(f"Index out of range in path component: '{p}'")

            # shift hardened indices
            index = index + HARDENED_OFFSET if hardened else index

            node = node.ced(index)

        return node

    @classmethod
    def from_seed(cls, seed: bytes) -> SimpleHDNode:
        """Derive a master node from a seed (16-64 bytes)"""
        if not (16 <= len(seed) <= 64):
            raise ValueError("Invalid seed length")

        master_entropy = parse256(seed[:32])
        master_chaincode = seed[32:]

        return cls(master_entropy, master_chaincode)

    def __repr__(self) -> str:
        return (
            "SimpleHDNode("
            f"depth={self.depth}, "
            f"index={self.index}, "
            f"entropy={self._entropy}, "
            f"chaincode={self._chaincode}"
            ")"
        )


def run_tests(testfile: str):
    print(f"Running Test Vectors from {testfile}")

    with open(testfile) as f:
        data = json.load(f)

    passed, failed = 0, 0
    for tv in data["test_vectors"]:
        tv_id = tv["id"]

        print(f"\nTest Vector {tv_id}\n{"*" * 40}")

        # given
        mnemonic = tv["given"]["mnemonic"]
        passphrase = (
            "" if tv["given"]["passphrase"] is None else tv["given"]["passphrase"]
        )
        paths = tv["given"]["derivationPaths"]
        # intermediate
        derived_keys = tv["intermediary"]["derivedKeys"]
        leaves = tv["intermediary"]["leaves"]
        merkle_root = tv["intermediary"]["merkleRoot"]
        # expected
        expected_scriptPubKey = tv["expected"]["scriptPubKey"]
        expected_address = tv["expected"]["bip350Address"]

        seed = Mnemonic.to_seed(mnemonic, passphrase)
        master = SimpleHDNode.from_seed(seed)

        for i, (path, expected) in enumerate(zip(paths, derived_keys)):
            child = master.derive(path)

            # Seed and Chaincode Tests

            # check that we got the correct seed and chaincode
            seed = child.entropy
            chaincode = child.chaincode.hex()
            exp_seed = expected["childSeed"]
            exp_chaincode = expected["childChainCode"]

            seed_ok = f"{seed:064x}" == exp_seed
            chaincode_ok = chaincode == exp_chaincode

            if seed_ok and chaincode_ok:
                print(f"    PASS seed/chaincode for path = {path}")
                print(f"        seed: {seed:064x}\n        chaincode: {chaincode}")
            else:
                print(f"    FAIL seed/chaincode for path = {path}")
                if not seed_ok:
                    print(f"        childSeed expected: {exp_seed}, got: {seed:064x}")
                if not chaincode_ok:
                    print(
                        f"        childChainCode expected: {exp_chaincode}, got: {chaincode}"
                    )

            # Public Key Tests

            # check that we generate the same x-only pubkey
            if "xonlyPubkey" in expected:
                pubkey = pubkey_gen(seed.to_bytes(32, "big"))
                exp_pubkey = expected["xonlyPubkey"]

                pubkey_ok = pubkey.hex() == exp_pubkey
                if pubkey_ok:
                    print(f"    PASS xonlyPubkey: 0x{pubkey.hex()}")
                    print(f"        Even y? {has_even_y(pubkey)}")
                else:
                    print("    FAIL xonlyPubkey")
                    print(
                        f"        xonlyPubkey expected: {exp_pubkey}, got: {pubkey.hex()}"
                    )
            # if SLH-DSA check that we generate the correct pubkey
            elif "publicKey" in expected:
                # TODO: do we want to extend with ChaCha20 like this?
                cipher = ChaCha20.new(key=seed.to_bytes(32, "big"), nonce=bytes(8))
                seed = cipher.encrypt(bytes(128))
                pubkey = keygen(Algorithm.SLH_DSA_SHAKE_128S, seed).public_key
                exp_pubkey = expected["publicKey"]

                pubkey_ok = pubkey.hex() == exp_pubkey
                if pubkey_ok:
                    print(f"    PASS SLH-DSA Pubkey: 0x{pubkey.hex()}")
                else:
                    print("    FAIL SLH-DSA Pubkey")
                    print(
                        f"        SLH-DSA Pubkey expected: {exp_pubkey}, got: {pubkey.hex()}"
                    )
            else:
                raise ValueError("Unknown or No PubKey")

            if seed_ok and chaincode_ok and pubkey_ok:
                passed += 1
            else:
                failed += 1

    print(f"\n{passed} passed, {failed} failed out of {passed + failed} tests")


def main():
    run_tests("bitcointools/test/p2mr_pqhd_derivation_paths.json")


# Main()
if __name__ == "__main__":
    main()
