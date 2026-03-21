import unittest
from unittest.mock import MagicMock, patch
import struct
from protocol.message import Message
from protocol.message_type import MessageType
from protocol.serializer import serialize
from server.connection_handler import ConnectionHandler

class TestConnectionHandler(unittest.TestCase):
    def setUp(self):
        self.mock_socket = MagicMock()
        self.mock_rsa = MagicMock()
        self.mock_router = MagicMock()
        self.handler = ConnectionHandler(self.mock_socket, self.mock_rsa, self.mock_router)

    def test_recv_message_unencrypted(self):
        msg = Message(MessageType.CLIENT_HELLO, {"test": "data"})
        serialized_msg = serialize(msg)
        header = struct.pack("!I", len(serialized_msg))
        
        self.mock_socket.recv.side_effect = [header, serialized_msg]
        
        received_msg = self.handler._ConnectionHandler__recv_message(encrypted=False)
        
        self.assertEqual(received_msg.type, MessageType.CLIENT_HELLO)
        self.assertEqual(received_msg.payload, {"test": "data"})

    def test_send_message_unencrypted(self):
        msg = Message(MessageType.SERVER_HELLO, {"test": "data"})
        serialized_msg = serialize(msg)
        header = struct.pack("!I", len(serialized_msg))
        
        self.handler._ConnectionHandler__send_message(msg, encrypted=False)
        
        self.mock_socket.sendall.assert_called_once_with(header + serialized_msg)

    @patch('server.connection_handler.HandshakeServer')
    def test_perform_handshake(self, MockHandshakeServer):
        mock_hs = MockHandshakeServer.return_value
        mock_hs.create_server_hello.return_value = Message(MessageType.SERVER_HELLO, {"B": 456})
        mock_hs.derive_session_key.return_value = 123456789
        
        client_hello = Message(MessageType.CLIENT_HELLO, {"p": 23, "g": 5, "A": 123})
        serialized_ch = serialize(client_hello)
        header_ch = struct.pack("!I", len(serialized_ch))
        self.mock_socket.recv.side_effect = [header_ch, serialized_ch]
        
        self.handler._ConnectionHandler__perform_handshake()
        
        mock_hs.process_client_hello.assert_called_once()
        mock_hs.create_server_hello.assert_called_once()
        self.assertIsNotNone(self.handler.des)

if __name__ == "__main__":
    unittest.main()
