from math import log2

obfkey = "27c78118b7316105"

def bitlen(n):
    '''Returns the number of bits required to represent int n'''
    assert isinstance(n, int)
    return len(bin(n)[2:])

def txid_to_key(txid):
    '''Converts a bitcoin txid to corresponding LevelDB key'''
    pass

def key_to_txid(val):
    '''Converts a bitcoin LevelDB key to  corresponding TXID'''
    assert val[:1] == "43"
    txid = val[2:]

def concat(obfval) -> int:
    '''Concatenates obfuscation key with itself padding op to len(obstr)'''
    op = ""

    while len(op) < len(obfval):
        op += obfkey
    op = op[:len(obfval)]

    return int(op, 16)

def deobf(obfval: str) -> str:
    '''DeObfuscatse the value of a bitcoin LevelDB transaction'''
    try:
        obf = int(obfval, 16)
    except ValueError as e:
        print(e.args)

    op = concat(obfval)

    return hex(obf ^ op)


# should return
deobf("26c326d7353661dc7005d274976f458691f24f0f05d141335f4ad5927e41")
