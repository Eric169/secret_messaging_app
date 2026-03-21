from protocol.message import Message
from protocol.message_type import MessageType

def get_messages_handler(message: Message, context) -> Message:
    db = context.get("db")
    if not db:
        return Message(MessageType.ERROR, {"error": "No database connection"})

    username = message.payload.get("username")
    authenticated_user = context.get("username")
    
    # print(f"[DEBUG] GET_MESSAGES verify: AuthUser={authenticated_user}, TargetUser={username}, Context ID={id(context)}", flush=True)

    if not username:
        return Message(MessageType.ERROR, {"error": "Missing username"})
    
    if not authenticated_user or authenticated_user != username:
        return Message(MessageType.ERROR, {"error": "Unauthorized access"})

    conn = db.get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT sender, ciphertext, timestamp FROM messages WHERE recipient = ?", (username,))
    rows = cursor.fetchall()
    
    messages = [{"sender": r[0], "ciphertext": r[1], "timestamp": r[2]} for r in rows]
    
    # Clear messages once fetched
    cursor.execute("DELETE FROM messages WHERE recipient = ?", (username,))
    conn.commit()
    conn.close()

    return Message(MessageType.OK, {"messages": messages})
