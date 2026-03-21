import unittest
from protocol.hash_helper import hash_password, verify_password, pre_hash_password

class TestPasswordSecurity(unittest.TestCase):

    def test_hashing_basic(self):
        password = "mysecurepassword"
        hashed = hash_password(password)
        self.assertTrue(verify_password(password, hashed))

    def test_wrong_password(self):
        password = "mysecurepassword"
        hashed = hash_password(password)
        self.assertFalse(verify_password("wrongpassword", hashed))

    def test_different_salts(self):
        password = "password123"
        hashed1 = hash_password(password)
        hashed2 = hash_password(password)
        self.assertNotEqual(hashed1, hashed2)
        self.assertTrue(verify_password(password, hashed1))
        self.assertTrue(verify_password(password, hashed2))

    def test_invalid_hash_format(self):
        self.assertFalse(verify_password("password", "invalid_hash"))

    def test_hybrid_flow(self):
        password = "mysecurepassword"
        username = "eric"
        pre_hash = pre_hash_password(password, username)
        stored_hash = hash_password(pre_hash)
        self.assertTrue(verify_password(pre_hash, stored_hash))
        wrong_pre_hash = pre_hash_password("wrong", username)
        self.assertFalse(verify_password(wrong_pre_hash, stored_hash))

if __name__ == "__main__":
    unittest.main()

