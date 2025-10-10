from enum import Enum
from typing import List
import binascii
import unittest
from helpers import get_tests


class Encoding(Enum):
    """enum type to list supported encodings"""

    BECH32 = 1
    BECH32M = 2


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3
BECH32_PREFIX = "bc"


def bech32_polymod(values: list) -> int:
    """compute checksum by taking values mod a (very) large polynomial"""
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1

    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0

    return chk


def bech32_hrp_expand(hrp):
    """expand the human readable part for checksum computation"""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp: str = "bc", data=None):
    """verify a Bech32 checksum given hrp and converted data chars"""
    if not data:
        raise ValueError("bech32 data portion must be provided")

    const = bech32_polymod(bech32_hrp_expand(hrp) + data)

    if const == 1:
        return Encoding.BECH32
    if const == BECH32M_CONST:
        return Encoding.BECH32M

    return None


# Bech32 checksum generation
def bech32_create_checksum(hrp: str = None, data=None, spec=None):
    """create a Bech32 checksum"""
    if not data:
        raise ValueError("bech32 data portion must be provided")

    values = bech32_hrp_expand(hrp) + data
    const = BECH32M_CONST if spec == Encoding.BECH32M else 1
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const

    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp, data, spec):
    """Compute a Bech32 string given hrp and data"""
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join([BECH32_CHARSET[c] for c in combined])


def bech32_decode(bech):
    """Validate a Bech32/Bech32m string, and determine hrp and data"""
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (
        bech.lower() != bech and bech.upper() != bech
    ):
        return (None, None, None)

    bech = bech.lower()
    pos = bech.rfind("1")

    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None, None)

    if not all(c in BECH32_CHARSET for c in bech[pos + 1 :]):
        return (None, None, None)

    hrp = bech[:pos]
    data = [BECH32_CHARSET.find(c) for c in bech[pos + 1 :]]
    spec = bech32_verify_checksum(hrp, data)
    if not spec:
        return (None, None, None)

    return (hrp, data[:-6], spec)


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1

    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)

    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None

    return ret


def decode(hrp, addr):
    """Decode a SegWit address."""
    hrpgot, data, spec = bech32_decode(addr)
    if hrpgot != hrp:
        return (None, None)

    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)

    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return (None, None)
    if (
        data[0] == 0
        and spec != Encoding.BECH32
        or data[0] != 0
        and spec != Encoding.BECH32M
    ):
        return (None, None)

    return (data[0], decoded)


def encode(hrp, witver, witprog):
    """Encode a SegWit address."""
    spec = Encoding.BECH32 if witver == 0 else Encoding.BECH32M
    ret = bech32_encode(hrp, [witver] + convertbits(witprog, 8, 5), spec)

    if decode(hrp, ret) == (None, None):
        return None

    return ret


def s2w(script: str) -> List[int]:
    """Convert a script/witprog hex string to a List[int] of its bytes"""
    return [int(f"{script[i:i+2]}", 16) for i in range(0, len(script), 2)]


# TODO: Get rid of this function and prefer a better use of encode()
def get_bech32_address(
    taptree_root: str, witness_version: int = 1, hrp: str = "bc"
) -> str:
    """helper to generate  addresses from the taptree root"""
    spec = Encoding.BECH32 if witness_version == 0 else Encoding.BECH32M
    witness_program = s2w(taptree_root)
    data = [witness_version] + convertbits(witness_program, 8, 5)

    return bech32_encode(hrp, data, spec)


# These tests come from BIP-0350 by sipa, see: https://github.com/sipa/bech32/blob/master/ref/python/tests.py


def segwit_scriptpubkey(witver, witprog):
    """Construct a Segwit scriptPubKey for a given witness program."""
    return bytes([witver + 0x50 if witver else 0, len(witprog)] + witprog)


VALID_BECH32 = [
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
]

VALID_BECH32M = [
    "A1LQFN3A",
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
]

INVALID_BECH32 = [
    " 1nwldj5",  # HRP character out of range
    "\x7f" + "1axkwrx",  # HRP character out of range
    "\x80" + "1eym55h",  # HRP character out of range
    # overall max length exceeded
    "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    "pzry9x0s0muk",  # No separator character
    "1pzry9x0s0muk",  # Empty HRP
    "x1b4n0q5v",  # Invalid data character
    "li1dgmt3",  # Too short checksum
    "de1lg7wt" + "\xff",  # Invalid character in checksum
    "A1G7SGD8",  # checksum calculated with uppercase form of HRP
    "10a06t8",  # empty HRP
    "1qzzfhee",  # empty HRP
]

INVALID_BECH32M = [
    " 1xj0phk",  # HRP character out of range
    "\x7f" + "1g6xzxy",  # HRP character out of range
    "\x80" + "1vctc34",  # HRP character out of range
    # overall max length exceeded
    "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
    "qyrz8wqd2c9m",  # No separator character
    "1qyrz8wqd2c9m",  # Empty HRP
    "y1b0jsk6g",  # Invalid data character
    "lt1igcx5c0",  # Invalid data character
    "in1muywd",  # Too short checksum
    "mm1crxm3i",  # Invalid character in checksum
    "au1s5cgom",  # Invalid character in checksum
    "M1VUXWEZ",  # Checksum calculated with uppercase form of HRP
    "16plkw9",  # Empty HRP
    "1p2gdwpf",  # Empty HRP
]

VALID_ADDRESS = [
    [
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        "0014751e76e8199196d454941c45d1b3a323f1433bd6",
    ],
    [
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
        "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
    ],
    [
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
        "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
    ],
    ["BC1SW50QGDZ25J", "6002751e"],
    ["bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "5210751e76e8199196d454941c45d1b3a323"],
    [
        "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
        "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ],
    [
        "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
        "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
    ],
    [
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ],
]

INVALID_ADDRESS = [
    # Invalid HRP
    "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
    # Invalid checksum algorithm (bech32 instead of bech32m)
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
    # Invalid checksum algorithm (bech32 instead of bech32m)
    "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
    # Invalid checksum algorithm (bech32 instead of bech32m)
    "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
    # Invalid checksum algorithm (bech32m instead of bech32)
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
    # Invalid checksum algorithm (bech32m instead of bech32)
    "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
    # Invalid character in checksum
    "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
    # Invalid witness version
    "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
    # Invalid program length (1 byte)
    "bc1pw5dgrnzv",
    # Invalid program length (41 bytes)
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
    # Invalid program length for witness version 0 (per BIP141)
    "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
    # Mixed case
    "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
    # More than 4 padding bits
    "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
    # Non-zero padding in 8-to-5 conversion
    "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
    # Empty data section
    "bc1gmk9yu",
]

INVALID_ADDRESS_ENC = [
    ("BC", 0, 20),
    ("bc", 0, 21),
    ("bc", 17, 32),
    ("bc", 1, 1),
    ("bc", 16, 41),
]


class TestSegwitAddress(unittest.TestCase):
    """Unit test class for segwit addressess."""

    def test_valid_checksum(self):
        """Test checksum creation and validation."""
        for spec in Encoding:
            tests = VALID_BECH32 if spec == Encoding.BECH32 else VALID_BECH32M
            for test in tests:
                hrp, _, dspec = bech32_decode(test)
                self.assertTrue(hrp is not None and dspec == spec)
                pos = test.rfind("1")
                test = test[: pos + 1] + chr(ord(test[pos + 1]) ^ 1) + test[pos + 2 :]
                hrp, _, dspec = bech32_decode(test)
                self.assertIsNone(hrp)

    def test_invalid_checksum(self):
        """Test validation of invalid checksums."""
        for spec in Encoding:
            tests = INVALID_BECH32 if spec == Encoding.BECH32 else INVALID_BECH32M
            for test in tests:
                hrp, _, dspec = bech32_decode(test)
                self.assertTrue(hrp is None or dspec != spec)

    def test_valid_address(self):
        """Test whether valid addresses decode to the correct output."""
        for address, hexscript in VALID_ADDRESS:
            hrp = "bc"
            witver, witprog = decode(hrp, address)
            if witver is None:
                hrp = "tb"
                witver, witprog = decode(hrp, address)
            self.assertIsNotNone(witver, address)
            scriptpubkey = segwit_scriptpubkey(witver, witprog)
            self.assertEqual(scriptpubkey, binascii.unhexlify(hexscript))
            addr = encode(hrp, witver, witprog)
            self.assertEqual(address.lower(), addr)

    def test_invalid_address(self):
        """Test whether invalid addresses fail to decode."""
        for test in INVALID_ADDRESS:
            witver, _ = decode("bc", test)
            self.assertIsNone(witver)
            witver, _ = decode("tb", test)
            self.assertIsNone(witver)

    def test_invalid_address_enc(self):
        """Test whether address encoding fails on invalid input."""
        for hrp, version, length in INVALID_ADDRESS_ENC:
            code = encode(hrp, version, [0] * length)
            self.assertIsNone(code)


if __name__ == "__main__":
    print("\nRunning Bech32/Bech32m Tests...")

    # BIP-0341 Segwit v1 ("Taproot") / bech32 Encoding Tests
    # from https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
    V = get_tests("test/bip341_wallet_test_vectors.json")

    print("\nBIP-0341 Segwit v1 (Taproot) / bech32 Encoding Tests\n", "-" * 50)
    for v in V["scriptPubKey"]:
        tweaked_pubkey = v["intermediary"]["tweakedPubkey"]
        derived_addr = get_bech32_address(tweaked_pubkey)
        assert derived_addr == v["expected"]["bip350Address"]
        print(f"Test Passed {tweaked_pubkey} => {derived_addr}")

    # BIP-0360 Segwit v2 (P2TSH) / bech32 Encoding Tests
    # from https://github.com/jbride/bips/blob/p2tsh/bip-0360/ref-impl/common/tests/data/p2tsh_construction.json
    V = get_tests("test/p2tsh_construction.json")

    print("\nBIP-0360 Segwit v2 (P2TSH) / bech32 Encoding Tests\n", "-" * 50)
    for v in V["test_vectors"]:
        if v["intermediary"]["merkleRoot"] is None:
            print("Null Script Tree")
            continue
        merkle_root = v["intermediary"]["merkleRoot"]
        derived_addr = get_bech32_address(merkle_root, witness_version=2)
        assert derived_addr == v["expected"]["bip350Address"]
        print(f"Test Passed {merkle_root} => {derived_addr}")

    # BIP-0173 Bech32 / BIP-0350 Bech32m test vectors for v1+ witness addresses
    # from https://github.com/sipa/bech32/blob/master/ref/python/tests.py
    print("\nBIP-0173 / BIP-0350 bech32/bech32m Tests\n", "-" * 50)
    unittest.main()
