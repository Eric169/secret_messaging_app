import unittest

from protocol.handshake import HandshakeClient, HandshakeServer
from crypto.rsa import keygen, rsa
from crypto.diffie_hellman.diffie_hellman import DiffieHellman
from common.constants import DH_GENERATOR, DH_P

# For testing purposes, smaller RSA key size.
RSA_KEY_SIZE = 512

class TestHandshake(unittest.TestCase):

    def test_handshake_success(self):
        n_server, e_server, d_server = keygen.get_rsa_key(RSA_KEY_SIZE)
        server_rsa = rsa.RSA(n_server, e_server, d_server)

        n_client, e_client, d_client = keygen.get_rsa_key(RSA_KEY_SIZE)
        client_rsa = rsa.RSA(n_client, e_client, d_client)

        client_dh = DiffieHellman(DH_P, DH_GENERATOR)

        client = HandshakeClient(client_rsa, client_dh, server_rsa)
        server = HandshakeServer(server_rsa)

        client_hello = client.create_client_hello()
        server.process_client_hello(client_hello)

        server_hello = server.create_server_hello()
        client_session_key = client.process_server_hello(server_hello)

        server_session_key = server.derive_session_key()
        self.assertEqual(client_session_key, server_session_key)

    def test_invalid_signature(self):
        n_server, e_server, d_server = keygen.get_rsa_key(RSA_KEY_SIZE)
        server_rsa = rsa.RSA(n_server, e_server, d_server)

        n_client, e_client, d_client = keygen.get_rsa_key(RSA_KEY_SIZE)
        client_rsa = rsa.RSA(n_client, e_client, d_client)

        client_dh = DiffieHellman(DH_P, DH_GENERATOR)

        client = HandshakeClient(client_rsa, client_dh, server_rsa)
        server = HandshakeServer(server_rsa)

        client_hello = client.create_client_hello()

        # MITM
        client_hello.payload["A"] += 1

        with self.assertRaises(Exception):
            server.process_client_hello(client_hello)
    
if __name__ == "__main__":
    unittest.main()