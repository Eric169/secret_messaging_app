from protocol.message import Message
from protocol.message_type import MessageType
from common.constants import RESPONSE_OK, RESPONSE_ERROR

def send_message_handler(message: Message, context) -> Message:
    db = context.get("db")
    if not db:
        return Message(MessageType.ERROR, {"error": "No database connection"})

    recipient = message.payload.get("recipient")
    sender = message.payload.get("sender")
    ciphertext = message.payload.get("ciphertext")
    authenticated_user = context.get("username")

    if not recipient or not sender or not ciphertext:
        return Message(MessageType.ERROR, {"error": "Missing message data"})

    if not authenticated_user or authenticated_user != sender:
        return Message(MessageType.ERROR, {"error": "Unauthorized access"})

    conn = db.get_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO messages (recipient, sender, ciphertext) VALUES (?, ?, ?)",
                       (recipient, sender, ciphertext))
        conn.commit()
    except Exception as e:
        return Message(MessageType.ERROR, {"error": str(e)})
    finally:
        conn.close()

    return Message(MessageType.OK, {"status": RESPONSE_OK})
