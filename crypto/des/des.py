from crypto.des.tables import *
from crypto.des.utils import *
from common.utils import split_blocks
from common.config import DES_BLOCK_SIZE

class DES:
    def __init__(self, key: list[bool]):
        if (len(key) != 64):
            raise Exception("The key is not 64 bits")
        self.key = key
        self.subkeys = self.__generate_subkeys()
    
    def __generate_subkeys(self) -> list[list[bool]]:
        subkeys: list[list[bool]] = []
        key: list[bool] = permute(self.key, PC_1)
        C: list[bool] = key[:28]
        D: list[bool] = key[28:]
        for shift in LR:
            C = left_shift(C, shift)
            D = left_shift(D, shift)

            combined: list[bool] = C + D

            subkey: list[bool] = permute(combined, PC_2)

            subkeys.append(subkey)
        return subkeys
    
    def encrypt(self, plaintext: str) -> bytes:
        data = plaintext.encode()
        
        data = pad(data)

        blocks = split_blocks(data)

        cyphertext = b""

        for block in blocks:
            bits = bytes_to_bits(block)

            encrypted_bits = self.__encrypt_block(bits)

            cyphertext += bits_to_bytes(encrypted_bits)
        return cyphertext

    def decrypt(self, ciphertext: bytes) -> str:
        blocks = split_blocks(ciphertext)

        plaintext = b""

        for block in blocks:
            bits = bytes_to_bits(block)

            decrypted_bits = self.__decrypt_block(bits)

            plaintext += bits_to_bytes(decrypted_bits)
        plaintext = unpad(plaintext)

        return plaintext.decode()

    def __encrypt_block(self, block: list[bool]) -> list[bool]:
        return self.__encryption_decryption(block, True)

    def __decrypt_block(self, block: list[bool]) -> list[bool]:
        return self.__encryption_decryption(block, False)

    def __encryption_decryption(self, block: list[bool], encrypt: bool) -> list[bool]:
        subkeys = self.subkeys
        if not encrypt:
            subkeys = subkeys[::-1]

        block = permute(block, IP)
        left = block[:32]
        right = block[32:]

        for i in range(16):
            tmp = right

            right = expand(right, E)
            right = xor(right, subkeys[i])
            right = substitute(right, SBOXES)
            right = permute(right, P)
            right = xor(right, left)
            left = tmp
        
        combined = right + left
        return permute(combined, FP)