from hashes import tagged_hash
import helpers

class Leaf():
    def __init__(self, ver: int, script: str):
        self.ver = ver  # leaf version
        self.script = script

    def __str__():
        print(f"TapLeaf Version: {self.ver}")
        print(f"Script: {script}")


