from hashlib import sha256
from bitcointools.hashes import tagged_hash
from bitcointools.transaction import Transaction

# SigHash Types
SIGHASH_ALL = 0x1  # sign all inputs and outputs
SIGHASH_NONE = 0x2  # sign all inputs only
SIGHASH_SINGLE = 0x3  # sign all inputs and one corresponding output
SIGHASH_ANYONECANPAY = 0x80 #


# You can use logical operations to combine these into the other types
# SIGHASH_ANYONECANPAY | SIGHASH_ALL = b'0x81'   # sign one input and all outputs
# SIGHASH_ANYONECANPAY | SIGHASH_NONE = b'0x82'   # sign one input only
# SIGHASH_ANYONECANPAY | SIGHASH_SINGLE = b'0x83'  # sign one input and one corresponding output


SIGHASH_TYPES = [
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY | SIGHASH_ALL,
    SIGHASH_ANYONECANPAY | SIGHASH_NONE,
    SIGHASH_ANYONECANPAY | SIGHASH_SINGLE
]

def is_valid_hashtype(hash_type: int) -> bool:
    '''make sure we have a valid sighash type'''
    return hash_type in SIGHASH_TYPES

class SigningContext:
    '''class to contain the nuts and bolts context needed to produce a sighash'''
    def __init__(self, tx: Transaction, utxos: dict[OutPoint, TxOut]) -> None:
        self.tx = tx
        self.utxos = utxos

        # pre-compute some expensive parts
        prevouts = b''.join([txin.prevout.serialize() for txin in tx.inputs])
        amounts = b''.join([utxos[txin.prevout].amount.to_bytes(8, byteorder='little', signed=False) for txin in tx.inputs])
        scriptPubkeys   = b''.join([utxos[txin.prevout].scriptPubKey for txin in tx.inputs])
        sequences = b''.join([txin.sequence.to_bytes(4, byteorder='little', signed=False) for txin in tx.inputs])
        outputs = b''.join([txout.serialize() for txout in tx.outputs])

        # cache the hashes
        self.prevouts = sha256(prevouts)
        self.amounts = sha256(amounts)
        self.scriptPubkeys = sha256(scriptPubkeys)
        self.sequences = sha256(sequences)
        self.outputs = sha256(outputs)

        # pre-compute per-input serialization for ANYONECANPAY
        self.serialized_inputs = []
        for txin in tx.inputs:
            txout = self.utxos[txin.prevout]
            s = (txin.prevout.serialize() +
                 txout.amount.to_bytes(8, 'little') +
                 txout.scriptPubKey +
                 txin.sequence.to_bytes(4, 'little'))
            self.serialized_inputs.append(s)

    def taproot_sign(self, input_idx: int, hashtype: int, ext_flag: int = 0, annex: bytes = None, message_ext: bytes = None) -> bytes:
        '''compute the BIP-341 / Taproot common signature message for given input index.'''

        txin = self.tx.inputs[input_idx]

        # sanity check
        if annex and annex[0] != 0x50:
            raise ValueError("Annex must start with 0x50")
        if ext_flag != 0:
            raise ValueError("ext_flag must be 0 until a softfork defines otherwise")
        if message_ext:
            raise ValueError("message_ext must be empty until defined otherwise")
        if hashtype not in SIGHASH_TYPES:
            raise ValueError(f"Unknown sighash type: {hashtype}")
        if (hashtype & SIGHASH_SINGLE) == SIGHASH_SINGLE and (input_idx >= len(self.tx.outputs)):
            raise ValueError("SIGHASH_SINGLE without corresponding output")

        # construct the common signature message
        message = b"\x00"  # epoch
        message += hashtype.to_bytes(1, 'little')  # hash type
        message += self.tx.version.to_bytes(4, 'little')  # version
        message += self.tx.locktime.to_bytes(4, 'little')  # nLocktime

        # inputs / sequences hash
        if (hashtype & 0x80) != SIGHASH_ANYONECANPAY:
            message += self.prevouts
            message += self.amounts
            message += self.scriptPubkeys
            message += self.sequences

        # outputs hash
        if (hashtype & 0x03) not in [SIGHASH_NONE, SIGHASH_SINGLE]:
            message += self.outputs

        annex_present = int(bool(annex))
        message += (2 * ext_flag + annex_present).to_bytes(1, "little")

        # input-specific serialization
        if (hashtype & 0x80) == SIGHASH_ANYONECANPAY:
            # just sign this input
            message += self.serialized_inputs[input_idx]
        else:
            # sequence for this input
            message += txin.sequence.to_bytes(4, 'little')

        # annex serialization
        if annex_present:
            message += len(annex).to_bytes(1, 'little') + annex

        # SIGHASH_SINGLE output serialization
        if (hashtype & 0x03) == SIGHASH_SINGLE:
            txout = self.tx.outputs[input_idx]
            message += txout.serialize()

        # message extension (currently always empty if we got to here)
        if message_ext:
            message += message_ext

        return tagged_hash(b"TapSigHash", message)


