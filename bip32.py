"""
BIP-32 Implementation based on https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

Security note: Private key material is stored in zeroed bytearrays and can be
explicitly cleared via BIP32Node.wipe() or the context manager interface.
Intermediate integer values created during key derivation arithmetic are subject
to Python's garbage collector and cannot be guaranteed to be cleared from memory.
This implementation is not hardened against memory forensics or cold boot attacks.
"""

# TODO decide on using 2**31 or 0x80000000 throughout code, currently I use both

from __future__ import annotations

import struct
from ecdsa import SECP256k1, SigningKey
from ecdsa.ellipticcurve import INFINITY, Point
from .base58 import base58check, base58check_decode
from .hashes import hash160, hmac_sha512

XPRV_VERSION = bytes.fromhex("0488ADE4")  # mainnet xprv
XPUB_VERSION = bytes.fromhex("0488B21E")  # mainnet xpub
TPRV_VERSION = bytes.fromhex("04358394")  # testnet tprv
TPUB_VERSION = bytes.fromhex("043587CF")  # testnet tpub
KNOWN_VERSIONS = {XPRV_VERSION, XPUB_VERSION, TPRV_VERSION, TPUB_VERSION}
PRV_VERSIONS = {XPRV_VERSION, TPRV_VERSION}
PUB_VERSIONS = {XPUB_VERSION, TPUB_VERSION}

CURVE = SECP256k1
G = CURVE.generator
N = CURVE.order

##
## Helper Functions
##


def ser32(i: int) -> bytes:
    return struct.pack(">L", i)


def ser256(i: int) -> bytes:
    return i.to_bytes(32, "big")


def parse256(b: bytes) -> int:
    """De-serialize big-endian bytes to integer"""
    return int.from_bytes(b, "big")


def point_from_priv(privkey: int) -> Point:
    """Recover public key point from private key"""
    sk = SigningKey.from_secret_exponent(privkey, curve=CURVE)
    vk = sk.verifying_key

    return vk.pubkey.point


def point_from_compressed_bytes(key_data: bytes) -> Point:
    """Reconstruct elliptic curve point from 33-byte compressed pubkey"""
    # check valid length
    if len(key_data) != 33:
        raise ValueError(f"Expected 33 bytes, got {len(key_data)}")
    prefix = key_data[0]
    # check for valid prefix (parity)
    if prefix not in (0x02, 0x03):
        raise ValueError(f"Invalid compressed pubkey prefix: 0x{prefix:02x}")
    x = parse256(key_data[1:])
    p = CURVE.curve.p()
    y_sq = (pow(x, 3, p) + CURVE.curve.b()) % p
    y = pow(y_sq, (p + 1) // 4, p)
    # check for valid y coordinate
    if pow(y, 2, p) != y_sq:
        raise ValueError("Pubkey x coordinate has no valid y on curve!")
    y = y if (y % 2 == 0) == (prefix == 0x02) else p - y

    return Point(CURVE.curve, x, y)


def serP(P: Point) -> bytes:
    """Serialize a curve point to 33-byte compressed form"""
    x = P.x()
    y = P.y()

    return bytes([2 + (y & 1)]) + ser256(x)


##
## BIP-32 HD Nodes
##


# BIP32PublicNode (watch-only / neutered node)
class BIP32PublicNode:
    """BIP32PublicNode (watch-only / neutered node)"""

    def __init__(
        self,
        pubkey: Point,
        chaincode: bytes,
        depth: int = 0,
        parent_fingerprint: bytes = b"\x00\x00\x00\x00",
        index: int = 0,
    ):
        self.pub = pubkey

        # validate chaincode length
        if len(chaincode) != 32:
            raise ValueError("Invalid Chaincode length")
        self.chaincode = chaincode

        # validate depth
        if not (0 <= depth <= 255):
            raise ValueError("Invalid depth")
        self.depth = depth

        # validate fingerprint length
        if len(parent_fingerprint) != 4:
            raise ValueError("Invalid parent fingerprint")
        self.parent_fingerprint = parent_fingerprint

        # validate index
        if not (0 <= index < 2**32):
            raise ValueError("Invalid index")
        self.index = index

    # pubkey getter
    def pubkey(self) -> Point:
        return self.pub

    # fingerprint getter
    def fingerprint(self) -> bytes:
        return hash160(serP(self.pubkey()))[:4]

    # Public Parent => Public Child
    def ckd_pub(self, index: int) -> BIP32PublicNode:
        """Returns child public node given parent public key
        only defined for non-hardened indices"""

        # verify valid index
        if not (0 <= index < 2**32):
            raise ValueError("Invalid child index")

        # verify non-hardened index
        if index >= 2**31:
            raise ValueError("Cannot derive hardened child from public key")

        data = serP(self.pubkey()) + ser32(index)

        I = hmac_sha512(self.chaincode, data)
        IL, IR = I[:32], I[32:]

        # check for invalid scalar
        if (IL_int := parse256(IL)) >= N:
            raise ValueError("Invalid derivation")

        # generate the child point
        child_point = IL_int * G + self.pubkey()

        # make sure child point is not the point at infinity (invalid)
        if child_point == INFINITY:
            raise ValueError("Derived child is point at infinity")

        child_chaincode = IR

        # check for max depth
        if self.depth == 255:
            raise ValueError("Max depth reached!")

        return BIP32PublicNode(
            child_point, child_chaincode, self.depth + 1, self.fingerprint(), index
        )

    # xpub Serialization
    def xpub(self, network: str = "mainnet") -> str:
        # check valid network
        if network not in ("mainnet", "testnet"):
            raise ValueError(f"Unknown network {network}")

        version = XPUB_VERSION if network == "mainnet" else TPUB_VERSION
        key_data = serP(self.pubkey())
        payload = (
            version
            + bytes([self.depth])
            + self.parent_fingerprint
            + ser32(self.index)
            + self.chaincode
            + key_data
        )

        return base58check(payload)

    @classmethod
    def from_xkey(cls, xkey: str) -> BIP32PublicNode:
        version, depth, parent_fp, index, chaincode, key_data = validate_xkey(xkey)
        # check if wrong version
        if version in PRV_VERSIONS:
            raise ValueError(
                "xprv key passed to BIP32PublicNode.from_xkey() -- use BIP32Node.from_xkey()"
            )
        point = point_from_compressed_bytes(key_data)

        return cls(point, chaincode, depth, parent_fp, index)

    def __repr__(self):
        """Human-friendly representation of node"""
        index_str = f"{self.index - 2**31}'" if self.index >= 2**31 else str(self.index)

        return (
            f"BIP32PublicNode(depth={self.depth}, "
            f"index={index_str}, "
            f"fingerprint={self.fingerprint().hex()})"
        )


# BIP32Node (full private / HD node)
class BIP32Node(BIP32PublicNode):
    """BIP32Node (full private / HD node)

    Private key material is stored as a zeroed bytearray internally.
    Call wipe() explicitly when done, or use as a context manager:

        with BIP32Node.from_xkey(xprv) as node:
            child = node.ckd_priv(0)

    Note: Python's memory model does not guarantee that copies of the
    private key integer made during arithmetic (e.g. in ckd_priv) are
    cleared. This provides best-effort protection against lingering
    references, not full cryptographic memory hygiene."""

    def __init__(
        self,
        privkey: int,
        chaincode: bytes,
        depth: int = 0,
        parent_fingerprint: bytes = b"\x00\x00\x00\x00",
        index: int = 0,
    ):
        # check valid privkey range
        if not (0 < privkey < N):
            raise ValueError("Invalid private key")
        self._privkey_bytes = bytearray(ser256(privkey))

        # initialize BIP32PublicNode
        super().__init__(
            point_from_priv(privkey), chaincode, depth, parent_fingerprint, index
        )

    # privkey getter (converts from bytearray)
    @property
    def privkey(self) -> int:
        """Private key as an integer. Raises if node has been wiped."""
        if not self._privkey_bytes:
            raise ValueError("Private key has been wiped!")
        return parse256(self._privkey_bytes)

    # zeroize / wipe privkey bytes
    def wipe(self) -> None:
        """Zero private key material in place and mark node as wiped.
        After calling wipe(), any operation requiring the private key
        will raise ValueError. The public key and chaincode are retained."""
        for i in range(len(self._privkey_bytes)):
            self._privkey_bytes[i] = 0
        self._privkey_bytes = bytearray()

    # Child Key Derivation (private)
    def ckd_priv(self, index):
        """Returns child private key given parent keys
        if index >= 2^31 then hardened; else non-hardened"""

        # check valid index
        if not (0 <= index < 2**32):
            raise ValueError("Invalid child index")

        # check if hardened index
        hardened = index >= 0x80000000

        if hardened:
            data = b"\x00" + ser256(self.privkey) + ser32(index)
        else:
            data = serP(self.pubkey()) + ser32(index)

        I = hmac_sha512(self.chaincode, data)
        IL, IR = I[:32], I[32:]

        if (IL_int := parse256(IL)) >= N:
            raise ValueError("Invalid derivation")
        else:
            child_privkey = (IL_int + self.privkey) % N

        child_chaincode = IR

        if child_privkey == 0:
            raise ValueError("Invalid child privkey")

        if self.depth == 255:
            raise ValueError("Max depth reached!")
        else:
            return BIP32Node(
                child_privkey,
                child_chaincode,
                self.depth + 1,
                self.fingerprint(),
                index,
            )

    # xprv Serialization
    def xprv(self, network="mainnet"):
        # check valid network
        if network not in ("mainnet", "testnet"):
            raise ValueError(f"Unknown network {network}")

        version = XPRV_VERSION if network == "mainnet" else TPRV_VERSION
        key_data = b"\x00" + ser256(self.privkey)
        payload = (
            version
            + bytes([self.depth])
            + self.parent_fingerprint
            + ser32(self.index)
            + self.chaincode
            + key_data
        )

        return base58check(payload)

    # neutering
    def neuter(self):
        """Return a public-only node, stripping the private key"""
        return BIP32PublicNode(
            self.pubkey(),
            self.chaincode,
            self.depth,
            self.parent_fingerprint,
            self.index,
        )

    @classmethod
    def from_xkey(cls, xkey: str) -> BIP32Node:
        version, depth, parent_fp, index, chaincode, key_data = validate_xkey(xkey)

        # check for wrong version
        if version in PUB_VERSIONS:
            raise ValueError(
                "xpub passed to BIP32Node.from_xkey() -- use BIP32PublicNode.from_xkey()"
            )

        return cls(parse256(key_data[1:]), chaincode, depth, parent_fp, index)

    def __repr__(self):
        """Human-friendly representation of node"""
        index_str = f"{self.index - 2**31}'" if self.index >= 2**31 else str(self.index)

        return (
            f"BIP32Node(depth={self.depth}, "
            f"index={index_str}, "
            f"fingerprint={self.fingerprint().hex()})"
        )

    def __enter__(self) -> BIP32Node:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.wipe()
        return False  # do not suppress exceptions


# Master Key Generation (from seed)
def master_key_from_seed(seed: bytes) -> BIP32Node:
    """Derive the master private node from a seed"""
    # check valid seed length
    if not (16 <= len(seed) <= 64):
        raise ValueError("Invalid seed length")

    I = hmac_sha512(b"Bitcoin seed", seed)
    IL, IR = parse256(I[:32]), I[32:]

    # check for invalid seed
    if IL == 0 or IL >= N:
        raise ValueError("Invalid seed")

    master_privkey = IL
    master_chaincode = IR

    return BIP32Node(master_privkey, master_chaincode)


# Path Derivation
def derive_path(node: BIP32PublicNode, path: str) -> BIP32PublicNode:
    """Derive a node at given path. Supports both public / private nodes
    Raises ValueError if hardened step is requested on public-only node"""
    if path == "m":
        return node

    # check for invalid derivation path
    if not path.startswith("m/"):
        raise ValueError("Invalid derivation path")

    parts = path.split("/")[1:]

    for p in parts:
        hardened = p.endswith("'")
        # catch non-integer path components
        try:
            index = int(p[:-1]) if hardened else int(p)
        except ValueError:  # for instance, "m/foo" was given
            raise ValueError(f"Invalid path component: '{p}'")

        # check for negative indices pre-shift
        if index < 0 or index >= 2**31:
            raise ValueError(f"Index out of range in path component: '{p}'")

        # shift hardened indices
        index = index + 2**31 if hardened else index

        if isinstance(node, BIP32Node):
            node = node.ckd_priv(index)
        else:
            node = node.ckd_pub(index)  # raises if hardened

    return node


##
## Validation and Inspection
##
def validate_xkey(xkey: str):
    """
    Decodes and validates an xprv/xpub/tprv/tpub string.
    Raises ValueError with a descriptive message if invalid.
    Returns (version, depth, parent_fp, index, chaincode, key_data) if valid.
    """
    try:
        raw = base58check_decode(xkey)
    except ValueError as e:
        raise ValueError(f"base58check failure: {e}")

    if (l := len(raw)) != 78:
        raise ValueError(f"Invalid payload length: expected 78 bytes, got {l}")

    version = raw[0:4]
    depth = raw[4]
    parent_fp = raw[5:9]
    index = struct.unpack(">L", raw[9:13])[0]
    chaincode = raw[13:45]
    key_data = raw[45:78]

    if version not in KNOWN_VERSIONS:
        raise ValueError(f"Unknown version: {version.hex()}")

    if depth == 0:
        if parent_fp != b"\x00\x00\x00\x00":
            raise ValueError("Zero depth with non-zero parent fingerprint")
        if index != 0:
            raise ValueError("Zero depth with non-zero index")

    is_private = version in PRV_VERSIONS
    if is_private:
        if key_data[0] != 0x00:
            raise ValueError(
                f"xprv version but key prefix is 0x{key_data[0]:02x}, expected 0x00"
            )
        privkey_int = parse256(key_data[1:])
        if privkey_int == 0 or privkey_int >= N:
            raise ValueError(f"Private key not in valid range [1, N-1]")
    else:
        prefix = key_data[0]
        if prefix == 0x00:
            raise ValueError(
                "xpub version but key prefix is 0x00 (looks like xprv key_data)"
            )
        if prefix not in (0x02, 0x03):
            raise ValueError(
                f"Invalid pubkey prefix: 0x{prefix:02x} (expected 0x02 or 0x03)"
            )
        point_from_compressed_bytes(
            key_data
        )  # validates point is on curve and raises if invalid

    return version, depth, parent_fp, index, chaincode, key_data


def describe_xkey(xkey: str) -> None:
    version, depth, parent_fp, index, chaincode, key_data = validate_xkey(xkey)

    # decode version and adjust hardened indices
    if version == XPRV_VERSION:
        v = "Mainnet xprv"
    elif version == XPUB_VERSION:
        v = "Mainnet xpub"
    elif version == TPRV_VERSION:
        v = "Testnet tprv"
    elif version == TPUB_VERSION:
        v = "Testnet tpub"
    else:
        raise ValueError("Invalid version!")

    version_string = f"{v} (version: {version.hex()})"
    adjusted_index = f"{index - 0x80000000}'" if index >= 0x80000000 else str(index)

    print(
        "XKeyInfo(\n"
        f"type = {version_string}\n"
        f"depth = {depth}\n"
        f"parent_fp = {parent_fp.hex()}\n"
        f"index = {adjusted_index} ({index})\n"
        f"chaincode = {chaincode.hex()}\n"
        f"key_data = {key_data.hex()}\n"
        ")\n"
    )


# BIP-32 Valid Test Vectors: {name, seed, tests: {chain, ext_prv, ext_pub}}
# tv = { 'name': "Test vector ",
#         'seed': "",
#         'tests': { 1: {'chain': "",
#                        'xprv': "",
#                        'xpub': "" },
#                    2: {'chain': "",
#                        'xprv': "",
#                        'xpub': ""},
#                   }
#        }

# Test Vector 1
tv1 = {
    "name": "BIP-32, Test Vector 1",
    "seed": "000102030405060708090a0b0c0d0e0f",
    "tests": {
        1: {
            "chain": "m",
            "xprv": "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
            "xpub": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        },
        2: {
            "chain": "m/0'",
            "xprv": "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
            "xpub": "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        },
        3: {
            "chain": "m/0'/1",
            "xprv": "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
            "xpub": "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
        },
        4: {
            "chain": "m/0'/1/2'",
            "xprv": "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
            "xpub": "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
        },
        5: {
            "chain": "m/0'/1/2'/2",
            "xprv": "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
            "xpub": "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
        },
        6: {
            "chain": "m/0'/1/2'/2/1000000000",
            "xprv": "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
            "xpub": "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
        },
    },
}

# Test Vector 2
tv2 = {
    "name": "BIP-32, Test Vector 2",
    "seed": "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    "tests": {
        1: {
            "chain": "m",
            "xprv": "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
            "xpub": "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
        },
        2: {
            "chain": "m/0",
            "xprv": "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
            "xpub": "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
        },
        3: {
            "chain": "m/0/2147483647'",
            "xprv": "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
            "xpub": "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
        },
        4: {
            "chain": "m/0/2147483647'/1",
            "xprv": "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
            "xpub": "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
        },
        5: {
            "chain": "m/0/2147483647'/1/2147483646'",
            "xprv": "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
            "xpub": "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
        },
        6: {
            "chain": "m/0/2147483647'/1/2147483646'/2",
            "xprv": "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
            "xpub": "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
        },
    },
}

# Test Vector 3
# These vectors test for the retention of leading zeros. See bitpay/bitcore-lib#47 and iancoleman/bip39#58 for more information.
tv3 = {
    "name": "BIP-32, Test Vector 3",
    "seed": "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
    "tests": {
        1: {
            "chain": "m",
            "xprv": "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
            "xpub": "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
        },
        2: {
            "chain": "m/0'",
            "xprv": "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
            "xpub": "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
        },
    },
}

# Test Vector 4
# These vectors test for the retention of leading zeros. See btcsuite/btcutil#172 for more information.
tv4 = {
    "name": "BIP-32, Test Vector 4",
    "seed": "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
    "tests": {
        1: {
            "chain": "m",
            "xprv": "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
            "xpub": "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
        },
        2: {
            "chain": "m/0'",
            "xprv": "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
            "xpub": "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
        },
        3: {
            "chain": "m/0'/1'",
            "xprv": "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
            "xpub": "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
        },
    },
}

# BIP32 Invalid Test Vectors: {name, tests: {test_num {ext_prv/ext_pub {key, comment}}}}

# Test Vector 5
# These vectors test that invalid extended keys are recognized as invalid.
tv5 = {
    "name": "BIP-32, Test Vector 5",
    "tests": {
        1: {
            "xprv": {
                "key": "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
                "comment": "prvkey version / pubkey mismatch",
            },
            "xpub": {
                "key": "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
                "comment": "pubkey version / prvkey mismatch",
            },
        },
        2: {
            "xprv": {
                "key": "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
                "comment": "invalid prvkey prefix 04",
            },
            "xpub": {
                "key": "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
                "comment": "invalid pubkey prefix 04",
            },
        },
        3: {
            "xprv": {
                "key": "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
                "comment": "invalid prvkey prefix 01",
            },
            "xpub": {
                "key": "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
                "comment": "invalid pubkey prefix 01",
            },
        },
        4: {
            "xprv": {
                "key": "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
                "comment": "zero depth with non-zero parent fingerprint",
            },
            "xpub": {
                "key": "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
                "comment": "zero depth with non-zero parent fingerprint",
            },
        },
        5: {
            "xprv": {
                "key": "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
                "comment": "zero depth with non-zero index",
            },
            "xpub": {
                "key": "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
                "comment": "zero depth with non-zero index",
            },
        },
        6: {
            "xprv": {
                "key": "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
                "comment": "unknown extended key version",
            },
            "xpub": {
                "key": "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
                "comment": "unknown extended key version",
            },
        },
        7: {
            "xprv": {
                "key": "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
                "comment": "private key 0 not in 1..n-1",
            }
        },
        8: {
            "xprv": {
                "key": "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
                "comment": "private key n not in 1..n-1",
            }
        },
        9: {
            "xpub": {
                "key": "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
                "comment": "invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007",
            }
        },
        10: {
            "xprv": {
                "key": "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
                "comment": "invalid checksum",
            }
        },
    },
}

if __name__ == "__main__":
    # Test that hmac.update(a) + hmac.update(b) == hmac a || b)
    # key = b"secret"
    # first_message = b"first_part"
    # second_message = b"second_part"
    # combined = b"first_partsecond_part"

    # mac = hmac.new(key, digestmod=hashlib.sha512)
    # mac.update(first_message)
    # print(mac.hexdigest())
    # mac.update(second_message)
    # print(mac.hexdigest())

    # mac = hmac.new(key, combined, digestmod=hashlib.sha512)
    # print(mac.hexdigest())

    # BIP-32 Test Vectors
    for tv in [tv1, tv2, tv3, tv4]:
        print(f"Running {tv['name']}\n{25 * '#'}\nSeed: {tv['seed']}")
        seed = bytes.fromhex(tv["seed"])

        master = master_key_from_seed(seed)
        print("Master xprv:", master.xprv())
        print("Master xpub:", master.xpub())

        for _, t in tv["tests"].items():
            node = derive_path(master, t["chain"])
            expected_xpub = t["xpub"]
            assert (
                node.xpub() == expected_xpub
            ), f"Expected: {expected_xpub}\nGot: {node.xpub()}"
            expected_xprv = t["xprv"]
            assert (
                node.xprv() == expected_xprv
            ), f"Expected: {expected_xprv}\nGot: {node.xprv()}"

        print(f"\n{tv['name']} Passed!\n")

    # Test Vector 5
    print(f"Running {tv5['name']}\n{25 * '#'}")
    for test_num, t in tv5["tests"].items():
        for key_type in ["xprv", "xpub"]:
            if key_type not in t:
                continue
            try:
                validate_xkey(t[key_type]["key"])
                print(
                    f"  [{test_num}] {key_type} UNEXPECTEDLY PASSED  # {t[key_type]['comment']}"
                )
            except ValueError as e:
                print(
                    f"  [{test_num}] {key_type} correctly rejected: {e}  # {t[key_type]['comment']}"
                )

    # More Testing
    print(f"\nTesting xprv/xpub Decoding\n{25 * '#'}")
    xkey = "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"
    describe_xkey(xkey)
