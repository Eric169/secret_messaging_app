import unittest

from common.utils import *
from crypto.des import des

class TestDES(unittest.TestCase):
    def test_encryption_decryption(self):
        key = string_to_bits("Test_Key")
        cypher = des.DES(key)
        message = "Test Message"
        self.assertEqual(cypher.decrypt(cypher.encrypt(message)), message)

if __name__ == "__main__":
    unittest.main()