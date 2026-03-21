import unittest

from crypto.rsa import keygen, rsa
from hashlib import sha256

# For testing purposes, smaller RSA key size.
RSA_KEY_SIZE = 512

class TestRSA(unittest.TestCase):
    def test_encryption_decryption(self):
        n, e, d = keygen.get_rsa_key(RSA_KEY_SIZE)
        cypher = rsa.RSA(n, e, d)

        message = "Test Message"

        self.assertEqual(cypher.decrypt(cypher.encrypt(message.encode())).decode(),
                         message
        )

    def test_signature(self):
        n, e, d = keygen.get_rsa_key(RSA_KEY_SIZE)
        cypher = rsa.RSA(n, e, d)

        message = "Test Message"
        hash_int = int.from_bytes(sha256(message.encode()).digest(), "big")

        self.assertTrue(cypher.verify(cypher.sign(hash_int), hash_int))

    def test_signature_invalid(self):
        n, e, d = keygen.get_rsa_key(RSA_KEY_SIZE)
        cypher = rsa.RSA(n, e, d)

        message = "Test Message"
        fake_message = "Fake Message"

        hash_real = int.from_bytes(sha256(message.encode()).digest(), "big")
        hash_fake = int.from_bytes(sha256(fake_message.encode()).digest(), "big")

        self.assertFalse(cypher.verify(cypher.sign(hash_real), hash_fake))

if __name__ == "__main__":
    unittest.main()