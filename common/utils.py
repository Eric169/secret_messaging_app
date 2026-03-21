
def int_to_bits(x: int, size: int) -> list[bool]:
    return [(x >> i) & 1 == 1 for i in reversed(range(size))]

def string_to_bits(s: str) -> list[bool]:
    bits = []
    for c in s:
        binary = format(ord(c), '08b')
        bits.extend(b == '1' for b in binary)
    return bits

def split_blocks(data: bytes, size: int = 8) -> list[bytes]:
    return [data[i:i+size] for i in range(0, len(data), size)]
