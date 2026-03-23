from common.config import DES_BLOCK_SIZE
from common.utils import int_to_bits

def left_shift(bits: list[bool], n: int) -> list[bool]:
    return bits[n:] + bits[:n]

def permute(bits: list[bool], table: list[int]) -> list[bool]:
    return [bits[i - 1] for i in table]

def xor(a: list[bool], b: list[bool]) -> list[bool]:
    return [a[i] ^ b[i] for i in range(len(a))]

def expand(bits: list[bool], table: list[int]) -> list[bool]:
    return [bits[i - 1] for i in table]

def substitute(bits: list[bool], SBOXES: list[list[int]]) -> list[bool]:
    output = []

    for i in range(8):
        block = bits[i*6:(i+1)*6]

        row = (block[0] << 1) | block[5]

        column = (
            (block[1] << 3) |
            (block[2] << 2) |
            (block[3] << 1) |
            block[4]
        )

        idx = row * 16 + column

        value = SBOXES[i][idx]
        output.extend(int_to_bits(value, 4))

    return output

def pad(data: bytes, block_size: int = DES_BLOCK_SIZE) -> bytes:
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpad(data: bytes, block_size: int = DES_BLOCK_SIZE) -> bytes:
    if not data:
        return b""
    padding_len = data[-1]
    if padding_len < 1 or padding_len > block_size:
        return data
    
    padding = data[-padding_len:]
    if all(p == padding_len for p in padding):
        return data[:-padding_len]
    else:
        return data

def bytes_to_bits(data: bytes) -> list[bool]:
    bits = []

    for byte in data:
        for i in range(8):
            bits.append(bool((byte >> (7 - i)) & 1))

    return bits

def bits_to_bytes(bits: list[bool]) -> bytes:
    result = []

    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        
        result.append(byte)
    return bytes(result)
