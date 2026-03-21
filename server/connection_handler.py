import struct
import socket
from protocol.message import Message
from protocol.message_type import MessageType
from protocol.serializer import serialize, deserialize
from protocol.handshake import HandshakeServer
from protocol.hash_helper import hash_values
from crypto.des.des import DES
from common.utils import int_to_bits
from crypto.rsa.rsa import RSA
from common.constants import HEADER_LENGTH
from server.message_router import MessageRouter
from common.constants import ENCODING

class ConnectionHandler:
    def __init__(self, client_socket: socket.socket, server_rsa: RSA, router: MessageRouter, db=None):
        self.client_socket = client_socket
        self.server_rsa = server_rsa
        self.router = router
        self.db = db
        self.session_key = None
        self.des = None
        self.context = {"db": self.db}

    def handle(self) -> None:
        try:
            self.__perform_handshake()

            self.__message_loop()
        except Exception as e:
            print(f"Connection error: {e}")
        finally:
            self.client_socket.close()

    def __perform_handshake(self):
        handshake = HandshakeServer(self.server_rsa)

        msg = self.__recv_message(encrypted=False)
        if msg.type != MessageType.CLIENT_HELLO:
            raise Exception("Expected CLIENT_HELLO")
        
        handshake.process_client_hello(msg)

        server_hello = handshake.create_server_hello()
        self.__send_message(server_hello, encrypted=False)

        shared_secret = handshake.derive_session_key()
        
        # Decided to take the first 64 bit of the hash of the DH shared seret.
        key_hash = hash_values(shared_secret)
        key_bits = int_to_bits(key_hash, 256)[:64]
        self.des = DES(key_bits)

    def __message_loop(self):
        while True:
            try:
                msg = self.__recv_message(encrypted=True)
                
                response = self.router.route(msg, self.context)
                
                self.__send_message(response, encrypted=True)

            except EOFError:
                break
            except Exception as e:
                print(f"Error in message loop: {e}")
                break

    def __send_message(self, message: Message, encrypted=False):
        data = serialize(message)
        
        if encrypted and self.des:
            data = self.des.encrypt(data.decode(ENCODING))

        length = len(data)
        header = struct.pack("!I", length)
        self.client_socket.sendall(header + data)

    def __recv_message(self, encrypted=False) -> Message:
        header = self.__recv_all(HEADER_LENGTH)
        if not header:
            raise EOFError("Client closed connection")
        
        length = struct.unpack("!I", header)[0]
        data = self.__recv_all(length)
        if not data:
            raise EOFError("Incomplete message data")

        if encrypted and self.des:
            decrypted_str = self.des.decrypt(data)
            data = decrypted_str.encode(ENCODING)

        return deserialize(data)

    def __recv_all(self, n):
        data = b""
        while len(data) < n:
            packet = self.client_socket.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data
