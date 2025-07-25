from helpers import bytes_to_hex, get_compact_size, hex_to_bytes, reverse_bytes
from typing import List

PIZZA_BLOCK_N =  57051
PIZZA_BLOCK_HEX = "01000000d07146425f54ca9f2dbbf3aaf6329de356c9c816386908f4b978b701000000002efbbcbd4e1f8a3102de3a6f6061dbfd76bed5720052075adb7c2249ccf0b879df28f84b249c151c858249190101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704249c151c015bffffffff0100f2052a010000004341040b41aad4d7414081802d283c628579b84cfbd9b4d811f1cdd8e90b1df4c680350909d2595d67e10738b6d7da30f3234107f06c05a9665abe3d1b5c48ec2be4d1ac00000000"
PIZZA_TX_HEX = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704249c151c015bffffffff0100f2052a010000004341040b41aad4d7414081802d283c628579b84cfbd9b4d811f1cdd8e90b1df4c680350909d2595d67e10738b6d7da30f3234107f06c05a9665abe3d1b5c48ec2be4d1ac00000000"

class TxIn:
    '''Input class for Bitcoin transactions'''
    def __init__(self, txid: str=None, vout: int=None, scriptSig: str=None, sequence: int=0xffffffff):
        '''Initialize the Input'''

        # Transaction ID of the prev output we want to spend
        if not txid:
            raise ValueError("You must provide a hex string txid for each input")
        if not len(txid) == 64:
            raise ValueError("txid must be a 32-byte hex string for each input")
        self.txid = txid

        # VOUT we want to spend
        if not isinstance(vout, int):
            raise ValueError("You must provide an integer vout for each input")
        if vout.bit_length() // 8 > 4:
            raise ValueError("vout must be no larger than 4 bytes for each input")
        self.vout = vout

        # ScriptSig for prev output
        if not scriptSig:
            raise ValueError("You must provide a hex string scriptSig for each input")
        if not int(scriptSig, 16):
            raise ValueError("scriptSig must be a hex string")
        self.scriptSig_size = get_compact_size(len(scriptSig) // 2)  # size of the scriptSig in bytes
        self.scriptSig = scriptSig  # signature

        # Sequence for e.g. replace-by-fee
        if not (0x0 <= sequence and sequence <= 0xffffffff):
            raise ValueError("Sequence must be an integer between 0 and 0xffffffff")
        self.sequence = sequence

    def serialize(self):
        '''return the serialize data for this input'''
        b = hex_to_bytes(self.txid) + self.vout.to_bytes(4, 'little') + hex_to_bytes(self.scriptSig_size) + hex_to_bytes(self.scriptSig) + self.sequence.to_bytes(4, 'little')
        return b

class TxOut:
    '''Output class for Bitcoin transactions'''
    def __init__(self, amount: int=None, scriptPubKey: str=None):
        if not amount:
            raise ValueError("amount must be an integer num of satoshis you wish to spend")
        if not (0 <= amount and amount < 2100000000000000):
            raise ValueError("invalid amount, 0 < amount < 2100000000000000")
        self.amount = amount  # satoshis going to this output as an int

        # scriptPubKey for output
        if not scriptPubKey:
            raise ValueError("You must provide a scriptPubKey for every output")
        self.scriptPubKey_size = get_compact_size(len(scriptPubKey) // 2)
        self.scriptPubKey = scriptPubKey

    def serialize(self):
        '''return the serialized data for this output'''
        b = self.amount.to_bytes(8, 'little') + hex_to_bytes(self.scriptPubKey_size) + hex_to_bytes(self.scriptPubKey)
        return b

class Transaction:
    '''Base class for a Bitcoin P2PK/P2PKH transactions'''

    def __init__(self, inputs: List[TxIn]=None, outputs: List[TxOut]=None, locktime: int=0):
        '''Initialize transaction'''
        # version is little-endian
        self.version = 0x01.to_bytes(4, 'little')

        # TX Inputs
        if not inputs:
            raise ValueError("You must provide a list of valid Tx Inputs that you wish to spend.")
        self.input_cnt = get_compact_size(len(inputs))
        self.inputs = inputs

        # TX Outputs
        if not vout:
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
        '''serialize the transaction'''
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

class TaprootTransaction(Transaction):
    '''TaprootTransaction Class'''

    def __init__(self, version: int=0x02, vin: List[TxIn]=None, vout: List[TxOut]=None, locktime='ffffffff') -> TaprootTransaction:
        super().__init__(inputs=vin, outputs=vout, locktime=locktime)

        # Segwit
        if not (0 < version and version < 3):
            raise ValueError("version \in {0x1 (legacy), 0x2 (SegWit)}")
        self.version = version

        self.marker = b'\x00'
        self.flag = b'\x01'

    def serialize(self):
        '''return the transaction in raw form'''
        # version
        b = self.version.to_bytes(4, 'little')

        # marker/flag
        b += self.marker + self.flag

        # inputs
        b += hex_to_bytes(self.input_cnt)
        for i in self.inputs:
            b += i.serialize()

        # outputs
        b += hex_to_bytes(self.output_cnt)
        for o in self.outputs:
            b += o.serialize()

        # the Witness

        # locktime
        b += self.locktime.to_bytes(4, 'little')

def run_tests():
    pass

if __name__ == '__main__':
    run_tests()
