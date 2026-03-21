from protocol.message import Message
from protocol.message_type import MessageType
from common.constants import RESPONSE_OK, ERROR_INVALID_LOGIN, RESPONSE_ERROR
from protocol.hash_helper import verify_password

def login_handler(message: Message, context) -> Message:
    db = context.get("db")
    if not db:
        return Message(MessageType.ERROR, {"error": "No database connection"})

    username = message.payload.get("username")
    password_hash = message.payload.get("password_hash")

    if not username or not password_hash:
        return Message(MessageType.ERROR, {"error": "Missing login data"})


    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row and verify_password(password_hash, row[0]):
        context["username"] = username
        return Message(MessageType.OK, {"status": RESPONSE_OK})

    else:
        return Message(MessageType.ERROR, {"error": ERROR_INVALID_LOGIN})
