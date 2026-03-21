from crypto.primes.prime_generator import *
from crypto.math_utils.math_utils import *

def get_rsa_key(bits: int) -> tuple[int, int, int]:
    e = 65537

    p = get_prime(bits)
    q = get_prime(bits)

    while p == q:
        q = get_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    g, d, _ = extended_gcd(e, phi)

    # I need e to be prime with phi.
    if g != 1:
        return get_rsa_key(bits)
    d = d % phi

    return (n, e, d)
