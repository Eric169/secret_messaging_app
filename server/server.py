import socket
import threading
from common.config import SERVER_HOST, SERVER_PORT, SERVER_RSA_N
from common.constants import RSA_E
from server.config import SERVER_RSA_D
from crypto.rsa.rsa import RSA
from server.connection_handler import ConnectionHandler
from server.message_router import MessageRouter
from protocol.message_type import MessageType
from server.database import db

from server.handlers.auth.register import register_handler
from server.handlers.auth.login import login_handler
from server.handlers.messaging.send_message import send_message_handler
from server.handlers.messaging.get_messages import get_messages_handler
from server.handlers.messaging.get_public_key import get_public_key_handler

def start_server():
    print("Initializing database...")
    db.init_db()

    print("Loading static RSA keys...")
    server_rsa = RSA(SERVER_RSA_N, RSA_E, SERVER_RSA_D)
    print("RSA keys loaded.")

    router = MessageRouter()
    router.register_handler(MessageType.REGISTER, register_handler)
    router.register_handler(MessageType.LOGIN, login_handler)
    router.register_handler(MessageType.SEND_MESSAGE, send_message_handler)
    router.register_handler(MessageType.GET_MESSAGES, get_messages_handler)
    router.register_handler(MessageType.GET_PUBLIC_KEY, get_public_key_handler)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_HOST, SERVER_PORT))
        s.listen()
        print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

        while True:
            client_socket, addr = s.accept()
            print(f"Connected by {addr}")
            
            handler = ConnectionHandler(client_socket, server_rsa, router, db=db)
            client_thread = threading.Thread(target=handler.handle)
            client_thread.daemon = True
            client_thread.start()

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("\nShutting down server.")
