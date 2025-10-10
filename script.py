from helpers import get_compact_size
import opcode

MAX_SCRIPT_SIZE = 10000
MAX_SCRIPT_ELEMENT_SIZE = 520
MAX_SCRIPT_OPCODES = 201

class Script():
    '''Basic Bitcoin script class'''

    def __init__(script: str = None):
        if not script:
            raise ValueError("script.py: no script provided")
        self.script = script
        self.size = get_compact_size(script)

    def _parse_script():
        pass
    def serialize():
        pass
    def get_size():
        pass
