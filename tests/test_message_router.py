import unittest
from unittest.mock import MagicMock
from protocol.message import Message
from protocol.message_type import MessageType
from server.message_router import MessageRouter

class TestMessageRouter(unittest.TestCase):
    def setUp(self):
        self.router = MessageRouter()
        self.context = MagicMock()

    def test_route_successful(self):
        mock_handler = MagicMock(return_value=Message(MessageType.OK, {"status": "success"}))
        self.router.register_handler(MessageType.REGISTER, mock_handler)

        msg = Message(MessageType.REGISTER, {"username": "testuser"})
        
        response = self.router.route(msg, self.context)

        mock_handler.assert_called_once_with(msg, self.context)
        self.assertEqual(response.type, MessageType.OK)
        self.assertEqual(response.payload["status"], "success")

    def test_route_no_handler(self):
        msg = Message(MessageType.LOGIN, {"username": "testuser"})
        
        response = self.router.route(msg, self.context)

        self.assertEqual(response.type, MessageType.ERROR)
        self.assertIn("No handler for message type", response.payload["error"])

if __name__ == "__main__":
    unittest.main()
