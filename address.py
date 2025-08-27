'''
this script will generate a bitcoin addresses given valid public / private keys

WARNING: Do not use this script to generate anything, especially not any bitcoin addresses. This script is untested, incomplete, and probably doesn't even work.
Use is 100% at your own risk, and I assume no liability for anything that happens.
'''

from base58 import base58check_encode
from hashes import sha256, hash256, ripemd160, hash160
import params
import secp256k1
import sys

# Prefixes
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

def get_p2pk_address(pubkey: secp256k1.PublicKey, debug: bool = False):
    '''Generate a base58check encoded P2PK address from a given pubkey'''
    # Pay-to-Public-Key-Hash (P2PKH) - legacy bitcoin address format
    # pubkey = k * G  (mod p),  where [0 < k <= n-1] \in Z is some private key
    #                           G is the generator point for secp256k1, and  * is point multiplication
    #                           p is the prime modulus for secp256k1
    #                           n is the curve order
    # HASH256(HASH256(0x00 + RIPEMD160(SHA256(pubkey))) to derive checksum (the 4 MSB)
    # Base58CheckEncode(0x00 + RIPEMD160(SHA256(pubkey)) + checksum) to derive address

    if pubkey is None:
        print("Wot? pubkey is None",
              "\nusage: get_address(pubkey: secp256k1.PublicKey)")
        return None

    pub_addr = base58check_encode(pubkey)

    if debug:
        print(f"hashed_pubkey: {hashed_pubkey.hex()}")
        print(f"checksum: {checksum.hex()}")
        print(f"unencoded_addr: {unencoded_addr.hex()}")
        print(f"public_address: {pub_addr}")

    return pub_addr

def get_new_address():
    '''Generate a new keypair and address'''
    privkey, pubkey = get_keypair()
    address = get_p2pk_address(pubkey=pubkey)

    print(f"Private Key: {privkey.serialize()} -> {address}")

    return privkey, address

# TODO: combine these tests
def test_p2pk_from_privkey(privkey: str, addr: str = None, debug: bool = False):
    '''Test that the given P2PK address is generated from the given private key'''
    privkey, pubkey = get_keypair(privkey)
    address = get_p2pk_address(pubkey=pubkey, debug=debug)

    if addr is not None:
        if address == addr:
            print("Test Passed")
            print(f"Private Key: {privkey.serialize()} -> Public Key: {pubkey.serialize().hex()} -> Address: {address}\n")
            return True
        else:
            print("Test Failed")
            print(f"Expected: {addr},\t Got: {address}")
            return False

    print(f"Private Key: {privkey.serialize()} -> Public Key: {pubkey.serialize().hex()} -> Address: {address}\n")

def test_p2pk_from_pubkey(pubkey: str, addr: str, debug: bool = False) -> None:
    '''Test that the given P2PK address is generated from the given public key'''
    pubkey = secp256k1.PublicKey(bytes.fromhex(pubkey), raw=True)
    address = get_p2pk_address(pubkey=pubkey, debug=debug)

    print("\nTest Passed") if address == addr else print("\nTest Failed")
    print(f"Public Key: {pubkey.serialize().hex()} -> Address: {address}\n")

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

    # test_p2pk_from_privkey(ANDREAS_PRIVKEY_0, addr=ANDREAS_ADDRESS_0)
    test_p2pk_from_privkey(ANDREAS_PRIVKEY_1, addr=ANDREAS_COMPRESSED_ADDRESS_1)
    test_p2pk_from_privkey(ANDREAS_PRIVKEY_2, addr=ANDREAS_ADDRESS_2)

    # TODO WIF format

if __name__ == "__main__":
    if len(args := sys.argv) < 2:
        print("Generating a random address")
        get_new_address()
    else:
        priv_key = args[1]

    run_tests()
