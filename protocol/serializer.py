import json
from protocol.message import Message
from protocol.message_type import MessageType

def serialize(message: Message) -> bytes:
    data = {
        "type": message.type.value,
        "payload": message.payload
    }
    return json.dumps(data).encode()

def deserialize(data: bytes) -> Message:
    obj = json.loads(data.decode())
    msg_type = MessageType(obj["type"])
    return Message(msg_type, obj["payload"])
