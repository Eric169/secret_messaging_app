import unittest
import threading
import time
import os
import sqlite3
import socket
from protocol.message import Message
from protocol.message_type import MessageType
from client.connection import ServerConnection
from crypto.rsa.keygen import get_rsa_key
from crypto.rsa.rsa import RSA
from protocol.hash_helper import hash_values
from server.server import start_server
from server.database import db as server_db
from common.config import SERVER_HOST, SERVER_PORT

# For testing purposes, smaller RSA key size.
RSA_KEY_SIZE = 512

class TestUnauthorizedAccess(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_db_path = "test_server_data.db"
        if os.path.exists(cls.test_db_path):
            os.remove(cls.test_db_path)
        
        import server.database.db
        server.database.db.DB_PATH = cls.test_db_path
        
        cls.server_thread = threading.Thread(target=start_server)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.test_db_path):
            os.remove(cls.test_db_path)

    def setUp(self):
        n1, e1, d1 = get_rsa_key(RSA_KEY_SIZE)
        self.rsa1 = RSA(n1, e1, d1)
        self.conn1 = ServerConnection(SERVER_HOST, SERVER_PORT, self.rsa1)
        self.conn1.connect()
        
        n2, e2, d2 = get_rsa_key(RSA_KEY_SIZE)
        self.rsa2 = RSA(n2, e2, d2)
        self.conn2 = ServerConnection(SERVER_HOST, SERVER_PORT, self.rsa2)
        self.conn2.connect()

    def tearDown(self):
        self.conn1.close()
        self.conn2.close()

    def test_security_flow(self):
        reg_alice = Message(MessageType.REGISTER, {
            "username": "alice",
            "password_hash": str(hash_values("alice_pass")),
            "client_rsa_pub": {"n": self.rsa1.n, "e": self.rsa1.e}
        })
        self.conn1.send(reg_alice)
        self.assertEqual(self.conn1.receive().type, MessageType.OK)

        reg_bob = Message(MessageType.REGISTER, {
            "username": "bob",
            "password_hash": str(hash_values("bob_pass")),
            "client_rsa_pub": {"n": self.rsa2.n, "e": self.rsa2.e}
        })
        self.conn2.send(reg_bob)
        self.assertEqual(self.conn2.receive().type, MessageType.OK)

        get_msg_alice = Message(MessageType.GET_MESSAGES, {"username": "alice"})
        self.conn1.send(get_msg_alice)
        resp = self.conn1.receive()
        self.assertEqual(resp.type, MessageType.ERROR)
        self.assertEqual(resp.payload.get("error"), "Unauthorized access")

        login_alice = Message(MessageType.LOGIN, {
            "username": "alice",
            "password_hash": str(hash_values("alice_pass"))
        })
        self.conn1.send(login_alice)
        self.assertEqual(self.conn1.receive().type, MessageType.OK)

        get_msg_bob = Message(MessageType.GET_MESSAGES, {"username": "bob"})
        self.conn1.send(get_msg_bob)
        resp = self.conn1.receive()
        self.assertEqual(resp.type, MessageType.ERROR)
        self.assertEqual(resp.payload.get("error"), "Unauthorized access")

        send_as_bob = Message(MessageType.SEND_MESSAGE, {
            "recipient": "alice",
            "sender": "bob",
            "ciphertext": "fake content"
        })
        self.conn1.send(send_as_bob)
        resp = self.conn1.receive()
        self.assertEqual(resp.type, MessageType.ERROR)
        self.assertEqual(resp.payload.get("error"), "Unauthorized access")

        send_as_alice = Message(MessageType.SEND_MESSAGE, {
            "recipient": "bob",
            "sender": "alice",
            "ciphertext": "hello bob"
        })
        self.conn1.send(send_as_alice)
        self.assertEqual(self.conn1.receive().type, MessageType.OK)

        login_bob = Message(MessageType.LOGIN, {
            "username": "bob",
            "password_hash": str(hash_values("bob_pass"))
        })
        self.conn2.send(login_bob)
        self.assertEqual(self.conn2.receive().type, MessageType.OK)

        get_msg_bob = Message(MessageType.GET_MESSAGES, {"username": "bob"})
        self.conn2.send(get_msg_bob)
        resp = self.conn2.receive()
        self.assertEqual(resp.type, MessageType.OK)
        messages = resp.payload.get("messages", [])
        self.assertTrue(any(m['sender'] == 'alice' and m['ciphertext'] == 'hello bob' for m in messages))

if __name__ == "__main__":
    unittest.main()
