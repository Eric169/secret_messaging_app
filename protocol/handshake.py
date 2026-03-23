from crypto.rsa.rsa import RSA
from crypto.diffie_hellman.diffie_hellman import DiffieHellman
from protocol.message import Message
from protocol.message_type import MessageType
from protocol.hash_helper import *
from common.constants import DH_GENERATOR, DH_P

class HandshakeClient:
    def __init__(self, rsa: RSA, dh: DiffieHellman, server_pub_rsa: RSA):
        self.rsa = rsa
        self.dh = dh
        self.server_pub_rsa = server_pub_rsa

    def create_client_hello(self) -> Message:
        A = self.dh.generate_public()

        payload = {
            "A": A,
            "client_rsa_pub": {
                "n": self.rsa.n,
                "e": self.rsa.e
            }
        }

        signature = self.rsa.sign(hash_payload(payload))
        payload["signature"] = signature

        return Message(MessageType.CLIENT_HELLO, payload)

    def process_server_hello(self, message: Message) -> int:
        B = message.payload["B"]
        signature = message.payload["signature"]

        if not self.__verify_server_signature(B, signature):
            raise Exception("Invalid signature")

        shared = self.dh.compute_shared(B)
        return shared
    
    def __verify_server_signature(self, B: int, signature: int) -> bool:
        if not self.server_pub_rsa:
            raise Exception("Server public key not provided for verification")
        A = self.dh.generate_public()
        return self.server_pub_rsa.verify(signature, hash_values(A, B))


class HandshakeServer:
    def __init__(self, rsa: RSA):
        self.rsa = rsa

    def process_client_hello(self, message: Message) -> None:
        payload = message.payload

        p = DH_P
        g = DH_GENERATOR
        A = payload["A"]
        client_rsa_pub = payload["client_rsa_pub"]

        signature = payload["signature"]

        if not self.__verify_client_signature(payload, signature, client_rsa_pub):
            raise Exception("Invalid signature")

        self.dh = DiffieHellman(p, g)
        self.A = A

    def create_server_hello(self) -> Message:
        B = self.dh.generate_public()

        signature = self.rsa.sign(hash_values(self.A, B))

        return Message(
            MessageType.SERVER_HELLO,
            {
                "B": B,
                "signature": signature
            }
        )

    def derive_session_key(self) -> int:
        shared = self.dh.compute_shared(self.A)

        return shared

    def __verify_client_signature(self, payload: dict, signature: int, rsa_pub: dict) -> bool:
        rsa = RSA(rsa_pub["n"], rsa_pub["e"])
        payload_copy = payload.copy()
        payload_copy.pop("signature", None)
        return rsa.verify(signature, hash_payload(payload_copy))
