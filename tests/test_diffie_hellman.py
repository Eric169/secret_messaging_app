import unittest

from crypto.diffie_hellman.diffie_hellman import DiffieHellman

class TestDiffieHellman(unittest.TestCase):
    def test_shared_key(self):
        p = 23
        g = 5
        alice = DiffieHellman(p, g)
        bob = DiffieHellman(p, g)

        A = alice.generate_public()
        B = bob.generate_public()

        self.assertEqual(alice.compute_shared(B), bob.compute_shared(A))

if __name__ == "__main__":
    unittest.main()