from protocol.message import Message
from protocol.message_type import MessageType
from common.constants import RESPONSE_OK, RESPONSE_ERROR, ERROR_USER_EXISTS
from protocol.hash_helper import hash_password

def register_handler(message: Message, context) -> Message:
    db = context.get("db")
    if not db:
        return Message(MessageType.ERROR, {"error": "No database connection"})

    username = message.payload.get("username")
    password_hash = message.payload.get("password_hash")
    client_rsa_pub = message.payload.get("client_rsa_pub", {})
    public_key_n = client_rsa_pub.get("n")
    public_key_e = client_rsa_pub.get("e")

    if not username or not password_hash:
        return Message(MessageType.ERROR, {"error": "Missing registration data"})

    password_hash = hash_password(password_hash)

    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO users (username, password_hash, public_key_n, public_key_e) VALUES (?, ?, ?, ?)",
                       (username, password_hash, str(public_key_n), str(public_key_e)))
        conn.commit()
    except Exception as e:
        return Message(MessageType.ERROR, {"error": ERROR_USER_EXISTS})
    finally:
        conn.close()

    return Message(MessageType.OK, {"status": RESPONSE_OK})


