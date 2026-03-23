from crypto.math_utils.math_utils import *
from common.utils import split_blocks

class RSA:
    def __init__(self, n: int, e: int, d: int | None = None):
        self.n = n
        self.e = e
        self.d = d

        self.block_size = (self.n.bit_length() // 8) - 1
    
    def encrypt(self, data: bytes) -> list[int]:
        blocks = split_blocks(data, self.block_size)

        encrypted = []

        for block in blocks:
            m = int.from_bytes(block, "big")

            c = self.__encrypt_block(m)

            encrypted.append(c)
        return encrypted
    
    def __encrypt_block(self, block: int) -> int:
        return mod_exp(block, self.e, self.n)
    
    def decrypt(self, blocks: list[int]) -> bytes:
        result = b""

        for block in blocks:
            m = self.__decrypt_block(block)
            byte_length = (self.n.bit_length() + 7) // 8
            result += m.to_bytes(byte_length, "big")

        return result.lstrip(b"\x00")

    def __decrypt_block(self, block: int) -> int:
        if (self.d is None):
            raise Exception("Private key is missing")
        return mod_exp(block, self.d, self.n)

    def sign(self, message_hash: int) -> int:
        if (self.d is None):
            raise Exception("Private key is missing")
        return mod_exp(message_hash, self.d, self.n)

    def verify(self, signature: int, message_hash: int) -> bool:
        return mod_exp(signature, self.e, self.n) == message_hash
