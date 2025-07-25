from hashes import tagged_hash
import helpers

class Leaf():
    def __init__(self, ver: int, script: str):
        self.ver = ver  # leaf version
        self.script = script

    def __str__():
        print(f"TapLeaf Version: {self.ver}")
        print(f"Script: {script}")

def build_taptree(hashes: list, ):
    pass

def merkelize_scripts(scripts: list) -> int:
    '''Build Merkle tree from list of scripts and return root'''
    if not scripts:
        raise ValueError("Script list cannot be empty")

    leaves = [tagged_hash("TapLeaf", hex_to_bytes(s)) for s in scripts]

    while len(leaves) > 1:
        tmp_leaves = []
        for i in range(0, len(leaves), 2):
            if i+1 >= len(leaves):
                leaves.append(leaves[-1])
            left, right = sorted([leaves[i], leaves[i+1]])
            parent = tagged_hash("TapBranch", left + right)
            tmp_leaves.append(parent)
        leaves = tmp_leaves

    return leaves[0]
