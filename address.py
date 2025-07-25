'''
this script will generate a bitcoin addresses given valid public / private keys

WARNING: Do not use this script to generate anything, especially not any bitcoin addresses. This script is untested, incomplete, and probably doesn't even work.
Use is 100% at your own risk, and I assume no liability for anything that happens.
'''

# Transaction Types
# ------------------
# Pay-to-Public-Key (P2PK)
# Pay-to-Public-Key-Hash (P2PKH)
# Pay-to-Multi-Signature (P2MS)
# Pay-to-Script-Hash (P2SH)
# Pay-to-Script-Hash - Pay-to-Witness-Public-Key-Hash (P2SH-P2WPKH)
# Pay-to-Script-Hash - Pay-to-Witness-Public-Script-Hash (P2SH-P2WSH)
# Pay-to-Witness-Public-Key-Hash (P2WPKH)
# Pay-to-Witness-Public-Script-Hash (P2WSH)
# Pay-to-Taproot (P2TR)
# OP_RETURN

from hashes import sha256, hash256, ripemd160, hash160
import sys
import secp256k1
import params

# Base58 encoding
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

# Bech32
Bech32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Version Bytes
ZERO = P2PKH_VER = b'\x00'  # P2PK/P2PKH - Base58 result prefix 1
P2SH_VER = SEGWIT_VER = b'\x05'  # P2SH/P2WSH P2WSH Base58 result prefix 3
TESTNET_VER = b'\x6f'  # Base58 result prefix m or n
PRIVKEY_WIF = b'\x80'  # Base58 result prefix 5, K, or L

# Prefixes
Bech32_PREFIX = 'bc'
COMPRESSED_PUBKEY_PREFIX_02  = '02' # even
COMPRESSED_PUBKEY_PREFIX_03  = '03' # odd
UNCOMPRESSED_PUBKEY_PREFIX = '04'
WIF_PREFIX = '05'

def get_keypair(k: str = None):
    '''Generate a new public/private keypair on secp256k1'''
    if k is None:
        privkey = secp256k1.PrivateKey()
    else:
        assert 0 < int(k, 16) <= params.n
        privkey = secp256k1.PrivateKey(bytes.fromhex(k), raw=True)

    return (privkey, privkey.pubkey)

def get_address(privkey: secp256k1.PrivateKey = None, pubkey: secp256k1.PublicKey = None, type='p2pkh', debug: bool = False):
    '''Generate a base58check encoded bitcoin address from pubkey'''
    if type == 'p2pkh':
        # Pay-to-Public-Key-Hash (P2PKH) - legacy bitcoin addresses
            # pubkey = k * G  (mod p) where [0 < k <= n-1] \in Z is some private key
            # HASH256(HASH256(0x00 + RIPEMD160(SHA256(pubkey))) to derive checksum (the 4 MSB)
            # Base58CheckEncode(0x00 + RIPEMD160(SHA256(pubkey)) + checksum) to derive address
        if privkey is None and pubkey is None:
            print("Wot? get_address(privkey: secp256k1.PrivateKey = None, pubkey: secp256k1.PublicKey = None, type = ’p2pkh’ debug: bool = False)")
            return None

        if not privkey is None :
            pubkey = privkey.pubkey

        pub_addr = base58check_encode(pubkey)

        if debug:
            if privkey is not None:
                print(f"private_key: {privkey.serialize()} --> pubkey: {pubkey.serialize().hex()}")
            print(f"hashed_pubkey: {hashed_pubkey.hex()}")
            print(f"checksum: {checksum.hex()}")
            print(f"unencoded_addr: {unencoded_addr.hex()}")
            print(f"public_address: {pub_addr}")

        return pub_addr

    else:

        return None

def get_new_address():
    '''Generate a new keypair and address'''
    privkey, pubkey = get_keypair()
    address = get_address(pubkey=pubkey)

    print(f"Private Key: {privkey.serialize()} -> {address}")

    return privkey, address

def base58_encode(v):
    '''Encode a string using Base58
    h/t to github: fortesp/bitcoinaddress
    '''
    def iseq(s):  # there are diff versions
        return s

    origlen = len(v)
    v = v.lstrip(b'\0')
    newlen = len(v)

    p, acc = 1, 0
    for c in iseq(v[::-1]):
        acc += p * c
        p = p << 8

    result = ''
    while acc > 0:
        acc, mod = divmod(acc, 58)
        result += ALPHABET[mod]

    return (result + ALPHABET[0] * (origlen - newlen))[::-1]

def base58check_encode(pubkey: secp256k1.PublicKey):
    '''Base58Check encode the public key'''
    assert pubkey.serialize()[0] == 0x2 or pubkey.serialize()[0] == 0x3  # only compressed public keys

    hashed_pubkey = hash160(pubkey.serialize())
    unencoded_addr = ZERO + hashed_pubkey
    checksum = hash256(unencoded_addr)[:4]
    pub_addr = base58_encode(unencoded_addr + checksum)

    return pub_addr


# Bech32 checksum verif
def bech32_polymod(values):
    '''take values mod large polynomial'''
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(s):
    '''expand the humand readable part'''
    return [ord(x) >> 5 for x in s] | [0] + [ord(x) & 31 for x in s]

def bech32_verify_checksum(hrp: str='bc', data=None):
    '''verify a Bech32 checksum'''
    if not data:
        raise ValueError("bech32 data portion must be provided")
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

# Bech32 chemsum generation
def bech32_create_checksum(hrp: str=None, data=None):
    '''create a Bech32 checksum'''
    if not data:
        raise ValueError("bech32 data portion must be provided")
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(v: str=None):
    '''return the Bech32 encoding of a string'''
    if not v:
        raise ValueError("bech32 encoding requires v to be a hex string")
    v = bin(int(v, 16))[2:].zfill(len(v) * 4)
    if len(v) % 5:      # pad with zeros if needed
        v += '0' * (5 - len(v) % 5)
    v = [int(v[i:i+5], 2) for i in range(0, len(v), 5)]
    return v

# TODO: combine these tests
def test_p2pkh_from_privkey(privkey: str, addr: str = None, debug: bool = False):
    '''Test that the given P2PK address is generated from the given private key'''
    privkey, pubkey = get_keypair(privkey)
    address = get_address(pubkey=pubkey, debug=debug)

    if addr is not None:
        if address == addr:
            print("Test Passed")
            print(f"Private Key: {privkey.serialize()} -> Public Key: {pubkey.serialize().hex()} -> Address: {address}")
            return True
        else:
            print("Test Failed")
            print(f"Expected: {addr},\t Got: {address}")
            return False

    print(f"Private Key: {privkey.serialize()} -> Public Key: {pubkey.serialize().hex()} -> Address: {address}")

def test_p2pkh_from_pubkey(pubkey: str, addr: str = None, debug: bool = False) -> None:
    '''Test that the given P2PK address is generated from the given public key'''
    pubkey = secp256k1.PublicKey(bytes.fromhex(pubkey), raw=True)
    address = get_p2pkh_address(pubkey=pubkey, debug=debug)

    if addr is not None:
        print("Test Passed") if addr == address else print("Test Failed")

    print(f"Public Key: {pubkey.serialize().hex()} -> Address: {address}")

def run_tests():
    # example taken from Mastering Bitcoin v2 by Andreas Antonopoulos page 78
    # ANDREAS_PRIVKEY_0 = 'KxFC1jmwwCoACiCAWZ3eXa96mBM6tb3TYzGmf6YwgdGWZgawvrtJ' #TODO WIF-Compressed format
    # ANDREAS_ADDRESS_0 = '1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy'

    # example taken from Mastering Bitcoin v2 by Andreas Antonopoulos page 77-78
    ANDREAS_PRIVKEY_1 = '3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa6'
    ANDREAS_PRIVKEY_DECIMAL_1 = 26563230048437957592232553826663696440606756685920117476832299673293013768870
    ANDREAS_PRIVKEY_WIF_1 = '5JG9hT3beGTJuUAmCQEEmNaxAuMacCTfXuw1R3FCXig23RQHMr4K'
    ANDREAS_PRIVKEY_HEX_COMPRESSED_1 = '3aba4162c7251c891207b747840551a71939b0de081f85c4e44cf7c13e41daa601'
    ANDREAS_PRIVKEY_WIF_COMPRESSED_1 = 'KyBsPXxTuVD82av65KZkrGrWi5qLMah5SdNq6uftawDbgKa2wv6S'
    ANDREAS_PUBKEY_COORDINATES = (41637322786646325214887832269588396900663353932545912953362782457239403430124,
                                  16388935128781238405526710466724741593761085120864331449066658622400339362166)
    ANDREAS_PUBKEY_HEX_1 = '045c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec243bcefdd4347074d44bd7356d6a53c495737dd96295e2a9374bf5f02ebfc176'
    ANDREAS_COMPRESSED_PUBKEY_1 = '025c0de3b9c8ab18dd04e3511243ec2952002dbfadc864b9628910169d9b9b00ec'
    ANDREAS_ADDRESS_1 = '1thMirt546nngXqyPEz532S8fLwbozud8'
    ANDREAS_COMPRESSED_ADDRESS_1 = '14cxpo3MBCYYWCgF74SWTdcmxipnGUsPw3'

    # example taken from Mastering Bitcoin v2 by Andreas Antonopoulos page 78
    ANDREAS_PRIVKEY_2 = '038109007313a5807b2eccc082c8c3fbb988a973cacf1a7df9ce725c31b14776'
    ANDREAS_ADDRESS_2 = '1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK'

    #test_p2pkh_from_privkey(ANDREAS_PRIVKEY_0, addr=ANDREAS_ADDRESS_0) #TODO WIF format
    test_p2pkh_from_privkey(ANDREAS_PRIVKEY_1, addr=ANDREAS_COMPRESSED_ADDRESS_1)
    test_p2pkh_from_privkey(ANDREAS_PRIVKEY_2, addr=ANDREAS_ADDRESS_2)

if __name__ == "__main__":
    if len(args := sys.argv) < 2:
        print("Generating some random address")
        get_new_address()
    else:
        priv_key = args[1]

    run_tests()
