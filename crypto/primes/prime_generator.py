import secrets
from crypto.math_utils.math_utils import mod_exp

# Not using the extended version for now since the probability is already low enough.
K = 1
def is_prime(n: int) -> bool:
    for i in range(K):
        a = secrets.randbelow(n - 1) + 1
        if (mod_exp(a, n - 1, n) != 1):
            return False
    return True

def get_prime(bits: int) -> int:
    n = secrets.randbits(bits)
    while (not is_prime(n)):
        n = secrets.randbits(bits)
    return n