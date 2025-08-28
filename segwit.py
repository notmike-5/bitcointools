from bitcointools.helpers import parse_varint

def sanitize_segwit(tx_hex: int, debug: bool = False) -> int:
    '''Remove the offending pieces of a segwit transaction'''
    tx, i = bytes.fromhex(tx_hex), 0

    version = tx[i:i+4]; i += 4     # 4 bytes
    marker_flag = tx[i:i+2]; i += 2 # 2 bytes

    if not marker_flag == b'\x00\x01':
        raise ValueError(
            f"This is not a SegWit Transaction.\
            version: {version.hex()}, marker: {hex(marker_flag[0])}, flag: {hex(marker_flag[1])}")

    input_cnt, i = parse_varint(tx, i)
    assert input_cnt < 0xfd

    if debug:
        print(f"version: {version.hex()}")
        print(f"marker: {marker_flag[0]:02x}")
        print(f"flag: {marker_flag[1]:02x}")
        print(f"inputs: {input_cnt}")

    inputs = []
    for _ in range(input_cnt):
        # Outpoint (txid: 32 bytes, vout: 4 bytes)
        txid = tx[i:i+32]
        vout = tx[i+32:i+36]; i += 36
        if debug:
            print(f"Input {_+1} Outpoint: txid={txid[::-1].hex()}, vout={int.from_bytes(vout, 'little')}")

        # ScriptSig length
        script_sig_len, i = parse_varint(tx, i)
        if debug:
            print(f"Input {_+1} ScriptSig Length: {script_sig_len}")

        # ScriptSig (should be empty for SegWit inputs)
        script_sig = tx[i:i+script_sig_len]; i += script_sig_len
        if debug:
            print(f"Input {_+1} ScriptSig: {script_sig.hex()}")

        # Sequence (4 bytes)
        sequence = tx[i:i+4]; i += 4
        if debug:
            print(f"Input {_+1} Sequence: {sequence.hex()} ({int.from_bytes(sequence, 'little'):08x})")

        # Store input for serialization (outpoint, scriptSig length=0, empty scriptSig, sequence)
        inputs.append(txid + vout + b'\x00' + sequence)

    output_cnt, i = parse_varint(tx, i)
    assert output_cnt < 0xfd

    if debug:
        print(f"outputs: {output_cnt}")

    outputs = []
    for _ in range(output_cnt):
        # Value (8 bytes)
        value = tx[i:i+8]; i += 8
        if debug:
            print(f"Output {_+1} Value: {int.from_bytes(value, 'little')} satoshis")

        # ScriptPubKey length (varint)
        script_pubkey_len, i = parse_varint(tx, i)
        if debug:
            print(f"Output {_+1} ScriptPubKey Length: {script_pubkey_len}")

        # ScriptPubKey
        script_pubkey = tx[i:i+script_pubkey_len]
        i += script_pubkey_len
        if debug:
            print(f"Output {i+1} ScriptPubKey: {script_pubkey.hex()}")

        # Store output (value, scriptPubKey length, scriptPubKey)
        outputs.append(value + bytes([script_pubkey_len]) + script_pubkey)

    witnesses = []
    for _ in range(input_cnt):
        # Witness stack item count
        witness_cnt, i = parse_varint(tx, i)
        if debug:
            print(f"Input {_+1} Witness Stack Item Count: {witness_cnt}")

        witness_items = []
        for j in range(witness_cnt):
            # Witness item length
            witness_len, i = parse_varint(tx, i)
            if debug:
                print(f"Input {_+1} Witness Item {j+1} Length: {witness_len}")

            # Witness item
            witness_item = tx[i:i+witness_len]
            i += witness_len
            if debug:
                print(f"Input {_+1} Witness Item {j+1}: {witness_item.hex()}")
            witness_items.append(witness_item)
        witnesses.append(witness_items)

    locktime = tx[i:i+4]; i += 4
    if debug:
        print(f"Locktime: {locktime.hex()} ({int.from_bytes(locktime, 'little')})")

    # Ensure all data is consumed
    if i != len(tx):
        raise ValueError(f"Unexpected data after locktime: {len(tx) - i} bytes remaining")

    serialized_non_witness = (
        version +
        bytes([input_cnt]) +
        b''.join(inputs) +
        bytes([output_cnt]) +
        b''.join(outputs) +
        locktime
    )

    return serialized_non_witness.hex()

def segwit_scriptpubkey(witver, witprog):
    '''Construct a Segwit scriptPubKey for a given witness program.'''
    return bytes([witver + 0x50 if witver else 0, len(witprog)] + witprog)
