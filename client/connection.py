import socket
import struct
from protocol.message import Message
from protocol.message_type import MessageType
from protocol.serializer import serialize, deserialize
from protocol.handshake import HandshakeClient
from protocol.hash_helper import hash_values
from crypto.des.des import DES
from common.utils import int_to_bits
from common.constants import HEADER_LENGTH, ENCODING, DH_GENERATOR, DH_P
from common.config import SERVER_RSA_N, SERVER_RSA_E
from crypto.rsa.rsa import RSA
from crypto.diffie_hellman.diffie_hellman import DiffieHellman
from protocol.hash_helper import hash_values

class ServerConnection:
    def __init__(self, host: str, port: int, client_rsa: RSA):
        self.host = host
        self.port = port
        self.client_rsa = client_rsa
        self.dh = DiffieHellman(DH_P, DH_GENERATOR)
        self.socket = None
        self.des = None

    def connect(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self.__perform_handshake()

    def __perform_handshake(self) -> None:
        server_pub_rsa = RSA(SERVER_RSA_N, SERVER_RSA_E)
        
        handshake = HandshakeClient(self.client_rsa, self.dh, server_pub_rsa)
        
        client_hello = handshake.create_client_hello()
        self.__send_message(client_hello, encrypted=False)
        
        server_hello = self.__recv_message(encrypted=False)
        if server_hello.type != MessageType.SERVER_HELLO:
            raise Exception("Expected SERVER_HELLO")
        
        shared_secret = handshake.process_server_hello(server_hello)
        
        key_hash = hash_values(shared_secret)
        key_bits = int_to_bits(key_hash, 256)[:64]
        self.des = DES(key_bits)

    def send(self, message: Message) -> None:
        self.__send_message(message, encrypted=True)

    def receive(self) -> Message:
        return self.__recv_message(encrypted=True)

    def __send_message(self, message: Message, encrypted=False) -> None:
        data = serialize(message)
        
        if encrypted and self.des:
            data = self.des.encrypt(data.decode(ENCODING))

        length = len(data)
        header = struct.pack("!I", length)
        self.socket.sendall(header + data)

    def __recv_message(self, encrypted=False) -> Message:
        header = self.__recv_all(HEADER_LENGTH)
        if not header:
            raise EOFError("Server closed connection")
        
        length = struct.unpack("!I", header)[0]
        data = self.__recv_all(length)
        if not data:
            raise EOFError("Incomplete message data")

        if encrypted and self.des:
            decrypted_str = self.des.decrypt(data)
            data = decrypted_str.encode(ENCODING)

        return deserialize(data)

    def __recv_all(self, n) -> None | bytes:
        data = b""
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def close(self) -> None:
        if self.socket:
            self.socket.close()
