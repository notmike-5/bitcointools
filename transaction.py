
from typing import List

# import sys
# sys.path.append('..')
from helpers import bytes_to_hex, get_compact_size, hex_to_bytes, reverse_bytes
from hashes import hash256

class TxIn:
    '''Input class for Bitcoin transactions'''
    def __init__(self, txid: str=None, vout: int=None, scriptSig: str=None, sequence: int=0xffffffff):
        '''Initialize the Input'''

        # Transaction ID of the prev output we want to spend
        if not txid:
            raise ValueError("You must provide a hex string txid for each input")
        if not (isinstance(int(txid, 16), int) and len(txid) == 64):
            raise ValueError("txid must be a 32-byte hex string for each input")
        self.txid = txid

        # Vout we want to spend
        if not isinstance(vout, int):
            raise ValueError("You must provide an integer vout for each input")
        if vout.bit_length() // 8 > 4:
            raise ValueError("vout must be no larger than 4 bytes for each input")
        self.vout = vout

        # ScriptSig for prev output
        if not scriptSig:
            raise ValueError("You must provide a hex string scriptSig for each input")
        # if not int(scriptSig, 16):
        #     raise ValueError("scriptSig must be a hex string")
        self.scriptSig_size = get_compact_size(len(scriptSig) // 2)  # size of the scriptSig in bytes
        self.scriptSig = scriptSig  # signature

        # Sequence for e.g. replace-by-fee
        if not (0x0 <= sequence and sequence <= 0xffffffff):
            raise ValueError("Sequence must be an integer between 0 and 0xffffffff")
        self.sequence = sequence

    def serialize(self) -> bytes:
        '''return the serialize data for this input'''
        b = hex_to_bytes(self.txid)[::-1]
        b += self.vout.to_bytes(4, 'little')
        b += hex_to_bytes(self.scriptSig_size)
        b += hex_to_bytes(self.scriptSig)
        b += self.sequence.to_bytes(4, 'little')
        return b

class SegwitTxIn(TxIn):
    '''Segregated Witness (SegWit) transaction class, moves scriptSig to witness area'''

    def __init__(self, txid: str=None, vout: int=None, witness: List[int]=None, sequence: int=0xffffffff):
        '''Initialize the transaction'''
        super().__init__(txid=txid, vout=vout, scriptSig='00', sequence=sequence)

        self.segwit = True

        if not witness:
            raise ValueError("a witness is required for every SegWit input")
        self.witness = witness
        self.stack_size = get_compact_size(len(witness))

    def serialize(self):
        '''return the serialized blob for a segwit input'''
        b = hex_to_bytes(self.txid)[::-1]
        b += self.vout.to_bytes(4, 'little')
        b += b'\x00'  # no scriptSig
        b += self.sequence.to_bytes(4, 'little')
        return b

class TxOut:
    '''Output class for Bitcoin transactions'''
    def __init__(self, amount: int=None, scriptPubKey: str=None):
        # if not amount:
        #     raise ValueError("amount must be an integer num of satoshis you wish to spend")
        if not (0 <= amount and amount < 2100000000000000):
            raise ValueError("invalid amount, 0 < amount < 2100000000000000")
        self.amount = amount  # satoshis going to this output as an int

        # scriptPubKey for output
        if not scriptPubKey:
            raise ValueError("You must provide a scriptPubKey for every output")
        self.scriptPubKey_size = get_compact_size(len(scriptPubKey) // 2)
        self.scriptPubKey = scriptPubKey

    def serialize(self) -> bytes:
        '''return the serialized data for this output'''
        b = self.amount.to_bytes(8, 'little')
        b += hex_to_bytes(self.scriptPubKey_size)
        b += hex_to_bytes(self.scriptPubKey)
        return b

class Transaction:
    '''Base class for (Legacy) Bitcoin P2PK/P2PKH transactions'''

    def __init__(self, inputs: List[TxIn]=None, outputs: List[TxOut]=None, locktime: int=0):
        '''Initialize transaction'''

        self.version = 0x01.to_bytes(4, 'little')

        # TX Inputs
        if not inputs:
            raise ValueError("You must provide a list of valid Tx Inputs that you wish to spend.")
        self.input_cnt = get_compact_size(len(inputs))
        self.inputs = inputs

        # TX Outputs
        if not outputs:
            raise ValueError("You must provide a list of valid Tx Outputs that you wish to send to.")
        self.outputs = outputs
        self.output_cnt = get_compact_size(len(outputs))

        if not (0 <= locktime and locktime <= 0xffffffff):
            raise ValueError("locktime must be an integer s.t. 0 <= locktime <= 0xffffffff")
        self.locktime = locktime

    def get_txid(self):
        '''Generate the transaction ID'''
        return reverse_bytes(bytes_to_hex(hash256(hex_to_bytes(self.serialize()))))

    def serialize(self):
        '''Serialize the transaction'''
        # version
        b = self.version

        # inputs
        b += hex_to_bytes(self.input_cnt)
        for i in self.inputs:
            b += i.serialize()

        # outputs
        b += hex_to_bytes(self.output_cnt)
        for o in self.outputs:
            b += o.serialize()

        # locktime
        b += self.locktime.to_bytes(4, 'little')
        return bytes_to_hex(b)

class SegwitTransaction(Transaction):
    '''SegwitTransaction Class'''

    def __init__(self, version: int=0x02, vin: List[TxIn]=None, vout: List[TxOut]=None, locktime=0):
        '''Initialize SegWit Transaction'''
        super().__init__(inputs=vin, outputs=vout, locktime=locktime)

        # version
        if not (0 < version and version < 3):
            raise ValueError("version in {0x1 (legacy), 0x2 (SegWit)}")
        self.version = version

        # marker/flag
        self.marker = b'\x00' # must be 0x00
        self.flag = b'\x01'  # must be flag > 0x01. may change w/ future protocol versions.

    def get_txid(self) -> bytes:
        '''return the txid of the transaction (markerflag + witness excluded)'''
        b = self.version.to_bytes(4, 'little')
        b += hex_to_bytes(self.input_cnt)

        # TODO mixed case, some segwit and some non-segwit inputs
        for i in self.inputs:
            b += i.serialize()

        b += hex_to_bytes(self.output_cnt)
        for o in self.outputs:
            b += o.serialize()

        b += self.locktime.to_bytes(4, 'little')

        return reverse_bytes(bytes_to_hex(hash256(b)))

    def serialize(self) -> bytes:
        '''return the transaction in raw form'''
        # version
        b = self.version.to_bytes(4, 'little')

        # marker/flag
        b += self.marker
        b += self.flag

        # inputs
        b += hex_to_bytes(self.input_cnt)
        for i in self.inputs:
            b += i.serialize()

        # outputs
        b += hex_to_bytes(self.output_cnt)
        for o in self.outputs:
            b += o.serialize()

        # the Witness repeated...
        # (stack items, stack=[(item_0 size, item_0), (item_1_size, item_1), ...])
        for i in self.inputs:
            if i.segwit:
                b += hex_to_bytes(i.stack_size)  # add stack size
                for _ in i.witness:
                    b += hex_to_bytes(get_compact_size(len(_) // 2))
                    b += hex_to_bytes(_)  # add each stack item

        # locktime
        b += self.locktime.to_bytes(4, 'little')

        return bytes_to_hex(b)

class TaprootTransaction(SegwitTransaction):
    '''TaprootTransaction class'''

    def __init__(self, version: int=0x02, vin: List[TxIn]=None, vout: List[TxOut]=None, MAST: List[int]=None, locktime: int=0):
        '''Initialize Segwit v1, TaprootTransaction'''
        super().__init__(version=version, vin=vin, vout=vout, locktime=locktime)
        if MAST:
            pass

# Satoshi --> Hal (P2PK)
HAL_BLOCK_N = 170

# 10,000 btc pizza
PIZZA_BLOCK_N =  57043



#
# # Test Cases
#
# TEST = {'VIN': [{ "txid": "",
#             "vout": 0,
#             "scriptSig": "",
#             "sequence": 0}],
#         'VOUT': [{"amount": 0,
#                    "scriptPubkey": "" }],
#         'TXID': "",
#         'HASH': "",
#         'HEX': "", }



# Test: Satoshi --> Hal

SATHAL = { 'desc': "The first Bitcoin transaction between Satoshi and Hal Finney",
           'version': 1,
           'VIN':[{ "txid": "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9",
                   "vout": 0,
                   "scriptSig": "47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901",
                   "sequence": 4294967295,
                   "segwit": False }],
           'VOUT': [{"amount": 1000000000,
                    "scriptPubkey": "4104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac"},
                   {"amount": 4000000000,
                    "scriptPubkey": "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"}],
           'TXID': "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
           'HASH': "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
           'HEX': "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000" }



# Test: Early P2SH

P2SH_TEST = {'desc': "An early P2SH Transaction",
             'version': 1,
        'VIN': [{ "txid": "42a3fdd7d7baea12221f259f38549930b47cec288b55e4a8facc3c899f4775da",
            "vout": 0,
            "scriptSig": "473044022048d1468895910edafe53d4ec4209192cc3a8f0f21e7b9811f83b5e419bfb57e002203fef249b56682dbbb1528d4338969abb14583858488a3a766f609185efe68bca0121031a455dab5e1f614e574a2f4f12f22990717e93899695fb0d81e4ac2dcfd25d00",
            "sequence": 4294967295,
            "segwit": False}],
        'VOUT': [{"amount": 990000,
                   "scriptPubkey": "a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a87" }],
        'TXID': "40eee3ae1760e3a8532263678cdf64569e6ad06abc133af64f735e52562bccc8",
        'HASH': "40eee3ae1760e3a8532263678cdf64569e6ad06abc133af64f735e52562bccc8",
        'HEX': "0100000001da75479f893cccfaa8e4558b28ec7cb4309954389f251f2212eabad7d7fda342000000006a473044022048d1468895910edafe53d4ec4209192cc3a8f0f21e7b9811f83b5e419bfb57e002203fef249b56682dbbb1528d4338969abb14583858488a3a766f609185efe68bca0121031a455dab5e1f614e574a2f4f12f22990717e93899695fb0d81e4ac2dcfd25d00ffffffff01301b0f000000000017a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a8700000000" }



# Test: Segwit v0

Segwit_v0_Test = {'desc': "An early Segwit v0 transaction",
                  'version': 2,
                  'VIN': [{ "txid": "8c655da543f574b6af8b1cdeb15cf3cdee89395e43c574264521e81f6ede533a",
                            "vout": 54,
                            "witness": ["304402201250febbce0a5b333c2d715b869cb960f5abf1702192c7af6e112c6d6030be880220073c55f4814a064bf804d9ed16b57eaaeaafb536c4187e6260ef3fc61ca98a7701",
        "02e71911951e1f9799d5ccd05200ea0c18f786cb1bb45754d4a0799a06c2b80e80"],
                            'sequence': 4294967293,
                            'segwit': True }],
                  'VOUT': [{"amount": 82483801,
                            "scriptPubkey": "0014cfbd92a6337e8b6043552d6fc5c35c7e5062281e" }],
                  'TXID': "6cd9ff242a04dbb6b0683c2b8576c397f341b7f0c1747b206f878db597a4cd01",
                  'HASH': "2fda6b0f657b21d78d9979ec84476a7cd8204fbf2e4e09d704144f74f67557e1",
                  'HEX': "020000000001013a53de6e1fe821452674c5435e3989eecdf35cb1de1c8bafb674f543a55d658c3600000000fdffffff01599aea0400000000160014cfbd92a6337e8b6043552d6fc5c35c7e5062281e0247304402201250febbce0a5b333c2d715b869cb960f5abf1702192c7af6e112c6d6030be880220073c55f4814a064bf804d9ed16b57eaaeaafb536c4187e6260ef3fc61ca98a77012102e71911951e1f9799d5ccd05200ea0c18f786cb1bb45754d4a0799a06c2b80e8000000000" }



# Test: Taproot

First_P2TR_test = { 'desc': "the first P2TR tx",
                    'version': 1,
                    'VIN': [{ "txid": "5849051cf3ce36257a1d844e28959f368a35adc9520fb9679175f6cdf8c1f1d1",
                              "vout": 1,
                              "witness": ["a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174a"],
                             'segwit': True,
                             'sequence': 4294967293 }],
                    'VOUT': [{ "amount": 0,
                               "scriptPubkey": "6a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e20406269746275673432" },
                             { "amount": 67230,
                               "scriptPubkey": "5120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f9" }],
                    'TXID': "33e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac98799036",
                    'HASH': "af2fdc4c54270adfb2a65987a79ed2f0e771a779ea48bb0ef06095b48395f74d",
                    'HEX': "01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00" }

def run_test(test: dict, isSegwit = False):
    '''Run a single test'''

    inputs = []
    for i in test['VIN']:
        if i['segwit']:
            inputs.append(
                SegwitTxIn(txid=i['txid'], vout=i['vout'], witness=i['witness'], sequence=i['sequence']))
            isSegwit = True
        else:
            inputs.append(
                TxIn(txid=i['txid'], vout=i['vout'], scriptSig=i['scriptSig'], sequence=i['sequence']))

    outputs = []
    for o in test['VOUT']:
        outputs.append(
            TxOut(amount=o['amount'], scriptPubKey=o['scriptPubkey']))

    tx = SegwitTransaction(version=test['version'], vin=inputs, vout=outputs) if isSegwit else Transaction(inputs=inputs, outputs=outputs)

    print(f"TXID: {tx.get_txid()}")
    print(f"HEX: {tx.serialize()}")

    assert tx.get_txid() == test['TXID'], f"\nTest Failed: {test['desc']}\nExpected: {test['TXID']}\nGot:\t{tx.get_txid()}"
    assert tx.serialize() == test['HEX'], f"\nTest Failed: {test['desc']}\nExpected:{test['HEX']}\nGot:\t {tx.serialize()}"

    print(f"\nTest Passed: {test['desc']}\n")


def run_tests():
    run_test(SATHAL)
    run_test(P2SH_TEST)
    run_test(Segwit_v0_Test)
    run_test(First_P2TR_test)

if __name__ == '__main__':
    run_tests()
