from .hashes import hash160, hash256

# Base58 character set
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Version Bytes
ZERO = P2PKH_VER = b"\x00"  # P2PK/P2PKH - Base58 result prefix 1
P2SH_VER = SEGWIT_VER = b"\x05"  # P2SH/P2WSH P2WSH Base58 result prefix 3
TESTNET_VER = b"\x6f"  # Base58 result prefix m or n
PRIVKEY_WIF = b"\x80"  # Base58 result prefix 5, K, or L


def base58_encode(v):
    """Encode a string using Base58
    h/t to github: fortesp/bitcoinaddress
    """

    def iseq(s):  # there are diff versions
        return s

    origlen = len(v)
    v = v.lstrip(b"\0")
    newlen = len(v)

    p, acc = 1, 0
    for c in iseq(v[::-1]):
        acc += p * c
        p = p << 8

    result = ""
    while acc > 0:
        acc, mod = divmod(acc, 58)
        result += ALPHABET[mod]

    return (result + ALPHABET[0] * (origlen - newlen))[::-1]


def base58check(payload):
    checksum = hash256(payload)[:4]
    return base58_encode(payload + checksum)


def base58check_encode(pubkey: bytes):
    """Base58Check encode the public key"""
    assert pubkey[0] == 0x2 or pubkey[0] == 0x3  # only compressed public keys

    hashed_pubkey = hash160(pubkey)
    unencoded_addr = ZERO + hashed_pubkey
    pub_addr = base58check(unencoded_addr)
    # checksum = hash256(unencoded_addr)[:4]
    # pub_addr = base58_encode(unencoded_addr + checksum)

    return pub_addr


def base58_decode(s: str) -> bytes:
    """Pure base58 decoding (no checksum)"""
    num = 0
    for c in s:
        num = num * 58 + ALPHABET.index(c)

    # Convert big int back to bytes
    byte_length = (num.bit_length() + 7) // 8
    result = num.to_bytes(byte_length, "big")

    # Preserve leading zeros
    leading_zeros = len(s) - len(s.lstrip(ALPHABET[0]))

    return b"\x00" * leading_zeros + result


def base58check_decode(s: str) -> bytes:
    """
    Decodes a Base58Check-encoded string.
    Returns: full payload bytes (version prefix included), checksum already verified.
    Raises ValueError if checksum is invalid or string is malformed.
    """
    if not s:
        raise ValueError("Empty Base58Check string")

    decoded = base58_decode(s)

    if len(decoded) < 5:
        raise ValueError("Base58Check string too short")

    checksum = decoded[-4:]
    computed = hash256(decoded[:-4])[:4]

    if checksum != computed:
        raise ValueError("Invalid Base58Check checksum")

    return decoded[:-4]  # everything except the 4 checksum bytes


if __name__ == "__main__":
    # Example: Bitcoin mainnet address
    addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    version, payload = base58check_decode(addr)
    print(f"Version: {version} (0x{version:02x})")
    print(f"Payload (20 bytes): {payload.hex()}")
    # Should print → Version: 0 (0x00), payload = 62e907b15cbf27d5425399ebf6f0fb50ebb88f18

    # Example: WIF private key (compressed)
    wif = "KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ"
    version, privkey = base58check_decode(wif)
    print(f"WIF version: {version} (0x{version:02x})")  # usually 0x80
    print(f"Private key : {privkey.hex()}")
