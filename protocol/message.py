from protocol.message_type import MessageType

class Message:
    def __init__(self, msg_type: MessageType, payload: dict):
        self.type = msg_type
        self.payload = payload