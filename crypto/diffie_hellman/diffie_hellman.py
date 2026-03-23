import secrets
from crypto.math_utils.math_utils import mod_exp

class DiffieHellman:
    def __init__(self, p: int, g: int):
        self.p = p
        self.g = g
        self.private = secrets.randbelow(p - 2) + 2
    
    def generate_public(self) -> int:
        return mod_exp(self.g, self.private, self.p)
    
    def compute_shared(self, other_public: int) -> int:
        return mod_exp(other_public, self.private, self.p)
