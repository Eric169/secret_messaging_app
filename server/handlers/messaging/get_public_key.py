from protocol.message import Message
from protocol.message_type import MessageType

def get_public_key_handler(message: Message, context) -> Message:
    db = context.get("db")
    if not db:
        return Message(MessageType.ERROR, {"error": "No database connection"})

    username = message.payload.get("username")

    if not username:
        return Message(MessageType.ERROR, {"error": "Missing username"})

    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT public_key_n, public_key_e FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return Message(MessageType.OK, {
            "client_rsa_pub": {
                "n": int(row[0]),
                "e": int(row[1])
            }
        })
    else:
        return Message(MessageType.ERROR, {"error": "User not found"})
