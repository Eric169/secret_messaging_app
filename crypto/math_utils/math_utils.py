

def mod_exp(base: int, exp: int, mod: int) -> int:
    return pow(base, exp, mod)

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if (b == 0):
        return a, 1, 0
    else:
        d, x, y = extended_gcd(b, a % b)
        return d, y, x - (a//b)*y

def mod_inverse(a: int, m: int) -> int:
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m
