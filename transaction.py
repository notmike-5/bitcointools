from typing import List

from helpers import bytes_to_hex, get_compact_size, hex_to_ascii, hex_to_bytes, reverse_bytes
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

    def get_txid(self) -> int:
        '''Generate the transaction ID'''
        return reverse_bytes(bytes_to_hex(hash256(hex_to_bytes(self.serialize()))))

    def get_txhash(self) -> int:
        '''return transaction hash, this is identical to the txid for pre-segwit transactions'''
        return self.get_txid()

    def serialize(self) -> bytes:
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

    def __init__(self, version: int=0x02, vin: List[TxIn]=None, vout: List[TxOut]=None, locktime: int=0):
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

    def get_txhash(self) -> int:
        '''return the hash of the whole blob (witness + markerflag included)'''
        return reverse_bytes(bytes_to_hex(hash256(hex_to_bytes(self.serialize()))))

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

    def __init__(self, version: int=0x02, vin: List[TxIn]=None, vout: List[TxOut]=None, iPubkey: int=None, MAST: List[int]=None, locktime: int=0):
        '''Initialize Segwit v1, TaprootTransaction'''
        super().__init__(version=version, vin=vin, vout=vout, locktime=locktime)

# Satoshi --> Hal (P2PK)
HAL_BLOCK_N = 170

# 10,000 btc pizza
PIZZA_BLOCK_N =  57043

#
# # Test Cases
#
# TEST = {'Vin': [{ "segwit": bool
#                   "txid": "int" / hex str,
#                   "vout": int,
#                   "scriptSig": "int" / hex str,
#                   "sequence": int
#                   "witness": (req. for segwit) "int" / hex str }],

#         'Vout': [{"amount": int (# of sats),
#                   "scriptPubkey": "int" / hex str }],

#         'TXID': int / hex str,
#         'HASH': int / hex str,
#         'HEX': int / hex str,

#         ’nLocktime’: (optional) int }



# Test: Satoshi --> Hal

Sat_Hal_test = { 'desc': "The first Bitcoin transaction between Satoshi and Hal Finney",
           'version': 1,
           'Vin':[{ "txid": "0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9",
                    "vout": 0,
                    "scriptSig": "47304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901",
                    "sequence": 4294967295,
                    "segwit": False }],
           'Vout': [{"amount": 1000000000,
                     "scriptPubkey": "4104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac"},
                    {"amount": 4000000000,
                     "scriptPubkey": "410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac"}],
           'TXID': "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
           'HASH': "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
           'HEX': "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000" }



# Test: Early P2SH

P2SH_test = {'desc': "An early P2SH Transaction",
             'version': 1,
             'Vin': [{ "txid": "42a3fdd7d7baea12221f259f38549930b47cec288b55e4a8facc3c899f4775da",
                       "vout": 0,
                       "scriptSig": "473044022048d1468895910edafe53d4ec4209192cc3a8f0f21e7b9811f83b5e419bfb57e002203fef249b56682dbbb1528d4338969abb14583858488a3a766f609185efe68bca0121031a455dab5e1f614e574a2f4f12f22990717e93899695fb0d81e4ac2dcfd25d00",
                       "sequence": 4294967295,
                       "segwit": False}],
             'Vout': [{"amount": 990000,
                       "scriptPubkey": "a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a87" }],
             'TXID': "40eee3ae1760e3a8532263678cdf64569e6ad06abc133af64f735e52562bccc8",
             'HASH': "40eee3ae1760e3a8532263678cdf64569e6ad06abc133af64f735e52562bccc8",
             'HEX': "0100000001da75479f893cccfaa8e4558b28ec7cb4309954389f251f2212eabad7d7fda342000000006a473044022048d1468895910edafe53d4ec4209192cc3a8f0f21e7b9811f83b5e419bfb57e002203fef249b56682dbbb1528d4338969abb14583858488a3a766f609185efe68bca0121031a455dab5e1f614e574a2f4f12f22990717e93899695fb0d81e4ac2dcfd25d00ffffffff01301b0f000000000017a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a8700000000" }



# Test: Segwit v0

Segwit_v0_test = {'desc': "An early Segwit v0 transaction",
                  'version': 2,
                  'Vin': [{ "txid": "8c655da543f574b6af8b1cdeb15cf3cdee89395e43c574264521e81f6ede533a",
                            "vout": 54,
                            "witness": ["304402201250febbce0a5b333c2d715b869cb960f5abf1702192c7af6e112c6d6030be880220073c55f4814a064bf804d9ed16b57eaaeaafb536c4187e6260ef3fc61ca98a7701",
        "02e71911951e1f9799d5ccd05200ea0c18f786cb1bb45754d4a0799a06c2b80e80"],
                            'sequence': 4294967293,
                            'segwit': True }],
                  'Vout': [{"amount": 82483801,
                            "scriptPubkey": "0014cfbd92a6337e8b6043552d6fc5c35c7e5062281e" }],
                  'TXID': "6cd9ff242a04dbb6b0683c2b8576c397f341b7f0c1747b206f878db597a4cd01",
                  'HASH': "2fda6b0f657b21d78d9979ec84476a7cd8204fbf2e4e09d704144f74f67557e1",
                  'HEX': "020000000001013a53de6e1fe821452674c5435e3989eecdf35cb1de1c8bafb674f543a55d658c3600000000fdffffff01599aea0400000000160014cfbd92a6337e8b6043552d6fc5c35c7e5062281e0247304402201250febbce0a5b333c2d715b869cb960f5abf1702192c7af6e112c6d6030be880220073c55f4814a064bf804d9ed16b57eaaeaafb536c4187e6260ef3fc61ca98a77012102e71911951e1f9799d5ccd05200ea0c18f786cb1bb45754d4a0799a06c2b80e8000000000" }


# Taproot Lore by Michael Folkson, https://gnusha.org/pi/bitcoindev/HaQ-hY5Xi9DebQ3qteJXbi48IY8ojYlMWXeYrWcEFiKuy31TKY7lNAc42rTb2Sf_FMyhgCz9vp-cf8y-fVpFZ6XtWuR-sBsox1lOoSeGtxQ=@protonmail.com/

# Test: Taproot
# The first Taproot spend [3] was completed by bitbug42. It was a key path spend and the OP_RETURN in this first Taproot spend contained the message “I like Schnorr sigs and I cannot lie”.

First_P2TR_test = { 'desc': "the first P2TR tx",
                    'version': 1,
                    'Vin': [{ "txid": "5849051cf3ce36257a1d844e28959f368a35adc9520fb9679175f6cdf8c1f1d1",
                              "vout": 1,
                              "witness": ["a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174a"],
                             'segwit': True,
                             'sequence': 4294967293 }],
                    'Vout': [{ "amount": 0,
                               "scriptPubkey": "6a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e20406269746275673432" },
                             { "amount": 67230,
                               "scriptPubkey": "5120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f9" }],
                    'TXID': "33e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac98799036",
                    'HASH': "af2fdc4c54270adfb2a65987a79ed2f0e771a779ea48bb0ef06095b48395f74d",
                    'HEX': "01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00",
                    'nLocktime': 709631 }

# Test: Taproot
# achow had the second Taproot spend [4] but the first script path spend. He also spent from two Taproot vanity addresses beginning bc1ptapr00t which were presumably generated using his Rust Bitcoin Vanity Address Generator

P2TR_scriptpath_and_keypath_test = { 'desc': "the first transaction with both a P2TR scriptpath and a P2TR keypath input",
                                     'version': 2,
                                     'Vin': [{ "segwit": True,
                                               "txid": "e700b7b330e4b56c5883d760f9cbe4fa47e0f62b350e108f1767bc07a4bbc07b",
                                               "vout": 0,
                                               "witness": ["134896c42cd95680b048845847c8054756861ffab7d4abab72f6508d67d1ec0c590287ec2161dd7884983286e1cd56ce65c08a24ee0476ede92678a93b1b180c"],
                                               'sequence': 4294967294 },
                                             { "segwit": True,
                                               "txid": "e700b7b330e4b56c5883d760f9cbe4fa47e0f62b350e108f1767bc07a4bbc07b",
                                               "vout": 1,
                                               "witness": ["7b5d614a4610bf9196775791fcc589597ca066dcd10048e004cd4c7341bb4bb90cee4705192f3f7db524e8067a5222c7f09baf29ef6b805b8327ecd1e5ab83ca",
        "20f5b059b9a72298ccbefff59d9b943f7e0fc91d8a3b944a95e7b6390cc99eb5f4ac",
        "c0d9dfdf0fe3c83e9870095d67fff59a8056dad28c6dfb944bb71cf64b90ace9a7776b22a1185fb2dc9524f6b178e2693189bf01655d7f38f043923668dc5af45b"],
                                               "sequence": 4294967294 }],
                    'Vout': [{ "amount": 965300,
                               "scriptPubkey": "0014173fd310e9db2c7e9550ce0f03f1e6c01d833aa9" }],
                    'TXID': "37777defed8717c581b4c0509329550e344bdc14ac38f71fc050096887e535c8",
                    'HASH': "2fb9e9ff2c166ffbd48406f7b9362125b665da2a760540065250188417f048c2",
                    'HEX': "020000000001027bc0bba407bc67178f100e352bf6e047fae4cbf960d783586cb5e430b3b700e70000000000feffffff7bc0bba407bc67178f100e352bf6e047fae4cbf960d783586cb5e430b3b700e70100000000feffffff01b4ba0e0000000000160014173fd310e9db2c7e9550ce0f03f1e6c01d833aa90140134896c42cd95680b048845847c8054756861ffab7d4abab72f6508d67d1ec0c590287ec2161dd7884983286e1cd56ce65c08a24ee0476ede92678a93b1b180c03407b5d614a4610bf9196775791fcc589597ca066dcd10048e004cd4c7341bb4bb90cee4705192f3f7db524e8067a5222c7f09baf29ef6b805b8327ecd1e5ab83ca2220f5b059b9a72298ccbefff59d9b943f7e0fc91d8a3b944a95e7b6390cc99eb5f4ac41c0d9dfdf0fe3c83e9870095d67fff59a8056dad28c6dfb944bb71cf64b90ace9a7776b22a1185fb2dc9524f6b178e2693189bf01655d7f38f043923668dc5af45bffd30a00",
                    'nLocktime': 709631 }

# Test: Taproot
# sipa had the third Taproot spend. He also had the bronze medal for SegWit spends on SegWit activation in 2017, he was third then too. However, his vanity address game stepped up for Taproot. For SegWit he spent from one vanity address beginning 35Segwit. This time he spent from vanity addresses beginning bc1ptapr00tearly, bc1pay2tapr00t, bc1pmyusetapr00t, bc1partytaptap and this isn’t including all the vanity addresses that were sent to. He (with Greg Maxwell’s help) searched 2.4 quadrillion keys in a week.

p2tr_multi_keypath_input_test = {'desc': "early P2TR with multiple P2TR keypath inputs",
                                 'version': 2,
                                 'Vin': [{ "segwit": True,
                                      "txid": "89654cf2132da47e4e9fae1ae37ba1c1cb09923b85fa351e5cc0a3539c52e21e",
                                      "vout": 0,
                                      "sequence": 4294967295,
                                      "witness":[
"b23008b3e044d16078fc93ae4f342b6e5ba44241c598503f80269fd66e7ce484e926b2ff58ac5633be79857951b3dc778082fd38a9e06a1139e6eea41a8680c701"
                                    ]},
                                    { "segwit": True,
                                      "txid": "89654cf2132da47e4e9fae1ae37ba1c1cb09923b85fa351e5cc0a3539c52e21e",
                                      "vout": 1,
                                      "sequence": 4294967295,
                                      "witness": [
"be98ba2a47fce6fbe4f7456e5fe0c2381f38ed3ae3b89d0748fdbfc6936b68019e01ff60343abbea025138e58aed2544dc8d3c0b2ccb35e2073fa2f9feeff5ed01"
                                    ]},
                                    { "segwit": True,
                                      "txid": "89654cf2132da47e4e9fae1ae37ba1c1cb09923b85fa351e5cc0a3539c52e21e",
                                      "vout": 2,
                                      "sequence": 4294967295,
                                      "witness": [
"466d525b97733d4733220694bf747fd6e9d4b0b96ea3b2fb06b7486b4b8e864df0057481a01cf10f7ea06849fb4717d62b902fe5807a1cba03a46bf3a7087e9401"
                                    ]},
                                    { "segwit": True,
                                      "txid": "89654cf2132da47e4e9fae1ae37ba1c1cb09923b85fa351e5cc0a3539c52e21e",
                                      "vout": 3,
                                      "sequence": 4294967295,
                                      "witness": [
"8dbfbdd2c164005eceb0de04c317b9cae62b0c97ed33da9dcec6301fa0517939b9024eba99e22098a5b0d86eb7218957883ea9fc13b737e1146ae2b95185fcf901"
                                    ]}],
                            'Vout': [{"amount": 10911232,
                                      "scriptPubkey": "5120a457d0c0399b499ed2df571d612ba549ae7f199387edceac175999210f6aa39d"}],
                            'TXID': "83c8e0289fecf93b5a284705396f5a652d9886cbd26236b0d647655ad8a37d82",
                            'HASH': "3082fc10f52b5a2292753c983c77d066d221642a4b3983dc22aa2975f7036585",
                            'HEX': "020000000001041ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890000000000ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890100000000ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890200000000ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890300000000ffffffff01007ea60000000000225120a457d0c0399b499ed2df571d612ba549ae7f199387edceac175999210f6aa39d0141b23008b3e044d16078fc93ae4f342b6e5ba44241c598503f80269fd66e7ce484e926b2ff58ac5633be79857951b3dc778082fd38a9e06a1139e6eea41a8680c7010141be98ba2a47fce6fbe4f7456e5fe0c2381f38ed3ae3b89d0748fdbfc6936b68019e01ff60343abbea025138e58aed2544dc8d3c0b2ccb35e2073fa2f9feeff5ed010141466d525b97733d4733220694bf747fd6e9d4b0b96ea3b2fb06b7486b4b8e864df0057481a01cf10f7ea06849fb4717d62b902fe5807a1cba03a46bf3a7087e940101418dbfbdd2c164005eceb0de04c317b9cae62b0c97ed33da9dcec6301fa0517939b9024eba99e22098a5b0d86eb7218957883ea9fc13b737e1146ae2b95185fcf90100000000" ,
                            'nLocktime': 0 }

# Test: Taproot
# BitGo had the fourth Taproot spend [9] and the first Taproot multisig spend via the script path. The script used OP_CHECKSIG and OP_CHECKSIGVERIFY which have been modified with the Taproot upgrade to check Schnorr signatures but it didn’t use the new opcode OP_CHECKSIGADD that has been introduced for threshold (and multi) signatures. It contained an OP_RETURN message with “Thx Satoshi! ∞/21mil First Taproot multisig spend -BitGo”

p2tr_scriptpath_2_of_2_multisig_spend_test = { 'desc': "the first p2tr scriptpath 2-of-2 multisig spend",
                                               'version': 2,
                                               'Vin': [{ "segwit": True,
                                                         "txid": "5b79f5d6039c188613342eb13961dd7d1e1a0f90023d3eaed25fc85a29201bb4",
                                                         "vout": 0,
                                                         "sequence": 4294967293,
                                                         "witness": [
        "23b1d4ff27b16af4b0fcb9672df671701a1a7f5a6bb7352b051f461edbc614aa6068b3e5313a174f90f3d95dc4e06f69bebd9cf5a3098fde034b01e69e8e788901",
        "0fd4a0d3f36a1f1074cb15838a48f572dc18d412d0f0f0fc1eeda9fa4820c942abb77e4d1a3c2b99ccf4ad29d9189e6e04a017fe611748464449f681bc38cf39",
        "20febe583fa77e49089f89b78fa8c116710715d6e40cc5f5a075ef1681550dd3c4ad20d0fa46cb883e940ac3dc5421f05b03859972639f51ed2eccbf3dc5a62e2e1b15ac",
        "c02e44c9e47eaeb4bb313adecd11012dfad435cd72ce71f525329f24d75c5b9432774e148e9209baf3f1656a46986d5f38ddf4e20912c6ac28f48d6bf747469fb1"
                                                         ]}],
                                               'Vout': [{"amount": 0,
                                                         "scriptPubkey": "6a3a546878205361746f7368692120e2889e2f32316d696c20466972737420546170726f6f74206d756c7469736967207370656e64202d426974476f"}],
                                               'TXID': "905ecdf95a84804b192f4dc221cfed4d77959b81ed66013a7e41a6e61e7ed530",
                                               'HASH': "526a41ff7182577e3eff0af07b399d310e4d33def08eb847322d818f80cd0738",
                                               'HEX': "02000000000101b41b20295ac85fd2ae3e3d02900f1a1e7ddd6139b12e341386189c03d6f5795b0000000000fdffffff0100000000000000003c6a3a546878205361746f7368692120e2889e2f32316d696c20466972737420546170726f6f74206d756c7469736967207370656e64202d426974476f044123b1d4ff27b16af4b0fcb9672df671701a1a7f5a6bb7352b051f461edbc614aa6068b3e5313a174f90f3d95dc4e06f69bebd9cf5a3098fde034b01e69e8e788901400fd4a0d3f36a1f1074cb15838a48f572dc18d412d0f0f0fc1eeda9fa4820c942abb77e4d1a3c2b99ccf4ad29d9189e6e04a017fe611748464449f681bc38cf394420febe583fa77e49089f89b78fa8c116710715d6e40cc5f5a075ef1681550dd3c4ad20d0fa46cb883e940ac3dc5421f05b03859972639f51ed2eccbf3dc5a62e2e1b15ac41c02e44c9e47eaeb4bb313adecd11012dfad435cd72ce71f525329f24d75c5b9432774e148e9209baf3f1656a46986d5f38ddf4e20912c6ac28f48d6bf747469fb100000000",
                                               'nLocktime': 0 }

# Test: Taproot
# The first use of OP_CHECKSIGADD on mainnet was completed [10] by Alekos Filini using modified code [11] from the BDK (Bitcoin Dev Kit) library.
p2tr_opchecksigadd_test = { 'desc': "the first use of the new Tapscript opcode OP_CHECKSIGADD",
                            'version': 1,
                            'Vin': [{"segwit": True,
                                     "txid": "09347a39275641e291dff2d8beded236b6b1bb0f4a6ae40a50f67dce02cf7323",
                                     "vout": 0,
                                     "sequence": 4294967293,
                                     "witness": [                                         "0adf90fd381d4a13c3e73740b337b230701189ed94abcb4030781635f035e6d3b50b8506470a68292a2bc74745b7a5732a28254b5f766f09e495929ec308090b01",
"",
"20c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabaeac20b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333cba519c",
"c00000000000000000000000000000000000000000000000000000000000000001"
                                                ]},
                                    {"segwit": True,
                                     "txid": "777c998695de4b7ecec54c058c73b2cab71184cf1655840935cd9388923dc288",
                                     "vout": 0,
                                     "sequence": 4294967293,
                                     "witness": [                                   "4636070d21adc8280735383102f7a0f5978cea257777a23934dd3b458b79bf388aca218e39e23533a059da173e402c4fc5e3375e1f839efb22e9a5c2a815b07301",
"",
"20c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabaeac20b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333cba519c",
"c00000000000000000000000000000000000000000000000000000000000000001"
                                                 ]}],
                            'Vout': [{"amount": 0,
                                      "scriptPubkey": "6a29676d20746170726f6f7420f09fa5952068747470733a2f2f626974636f696e6465766b69742e6f7267"},
                                     {"amount": 1154670,
                                      "scriptPubkey": "76a91405070d0290da457409a37db2e294c1ffbc52738088ac"}],
                            'TXID': "2eb8dbaa346d4be4e82fe444c2f0be00654d8cfd8c4a9a61b11aeaab8c00b272",
                            'HASH': "19886d04721b18c202e34b6d9964e8f810563502ba3946e4c0cbd636d7e17157",
                            'HEX': "010000000001022373cf02ce7df6500ae46a4a0fbbb1b636d2debed8f2df91e2415627397a34090000000000fdffffff88c23d928893cd3509845516cf8411b7cab2738c054cc5ce7e4bde9586997c770000000000fdffffff0200000000000000002b6a29676d20746170726f6f7420f09fa5952068747470733a2f2f626974636f696e6465766b69742e6f72676e9e1100000000001976a91405070d0290da457409a37db2e294c1ffbc52738088ac04410adf90fd381d4a13c3e73740b337b230701189ed94abcb4030781635f035e6d3b50b8506470a68292a2bc74745b7a5732a28254b5f766f09e495929ec308090b01004620c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabaeac20b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333cba519c21c0000000000000000000000000000000000000000000000000000000000000000104414636070d21adc8280735383102f7a0f5978cea257777a23934dd3b458b79bf388aca218e39e23533a059da173e402c4fc5e3375e1f839efb22e9a5c2a815b07301004620c13e6d193f5d04506723bd67abcc5d31b610395c445ac6744cb0a1846b3aabaeac20b0e2e48ad7c3d776cf6f2395c504dc19551268ea7429496726c5d5bf72f9333cba519c21c0000000000000000000000000000000000000000000000000000000000000000100000000",
                            'nLocktime': 0 }

def run_test(test: dict):
    '''Run a single test'''

    isSegwit = False

    inputs = []
    for i in test['Vin']:
        if i['segwit']:
            inputs.append(
                SegwitTxIn(txid=i['txid'], vout=i['vout'], witness=i['witness'], sequence=i['sequence']))
            isSegwit = True
        else:
            inputs.append(
                TxIn(txid=i['txid'], vout=i['vout'], scriptSig=i['scriptSig'], sequence=i['sequence']))

    outputs = []
    for o in test['Vout']:
        outputs.append(
            TxOut(amount=o['amount'], scriptPubKey=o['scriptPubkey']))

    locktime = test['nLocktime'] if 'nLocktime' in test else 0

    if isSegwit:
        tx = SegwitTransaction(version=test['version'], vin=inputs, vout=outputs, locktime=locktime)
    else:
        tx = Transaction(inputs=inputs, outputs=outputs, locktime=locktime)

    assert tx.get_txid() == test['TXID'], f"\nTest Failed: {test['desc']}\nExpected: {test['TXID']}\nGot:\t{tx.get_txid()}"
    assert tx.serialize() == test['HEX'], f"\nTest Failed: {test['desc']}\nExpected:{test['HEX']}\nGot:\t {tx.serialize()}"
    assert tx.get_txhash() == test['HASH'], f"\nTest Failed: {test['desc']}\nExpected:{test['HASH']}\nGot:\t {tx.get_txhash()}"

    print(f"\nTest Passed: {test['desc']}\n")
    print(f"TXID: {tx.get_txid()}")
    print(f"TXHASH: {tx.get_txhash()}")
    print(f"HEX: {tx.serialize()}")


def run_tests():
    run_test(Sat_Hal_test)
    run_test(P2SH_test)
    run_test(Segwit_v0_test)
    run_test(First_P2TR_test)
    print("\nHidden Message!\t", hex_to_ascii(First_P2TR_test['Vout'][0]['scriptPubkey'][4:]))
    run_test(P2TR_scriptpath_and_keypath_test)
    run_test(p2tr_multi_keypath_input_test)
    run_test(p2tr_scriptpath_2_of_2_multisig_spend_test)
    print("\nHidden Message!\t", hex_to_ascii(p2tr_scriptpath_2_of_2_multisig_spend_test['Vout'][0]['scriptPubkey'][4:]))
    run_test(p2tr_opchecksigadd_test)

if __name__ == '__main__':
    run_tests()
