from protocol.message import Message
from protocol.message_type import MessageType

class MessageRouter:
    def __init__(self):
        self._handlers = {}

    def register_handler(self, msg_type: MessageType, handler_func) -> None:
        self._handlers[msg_type] = handler_func

    def route(self, message: Message, context) -> Message:
        handler = self._handlers.get(message.type)
        if not handler:
            return Message(MessageType.ERROR,
                           {"error": f"No handler for message type: {message.type.value}"})
        
        return handler(message, context)
