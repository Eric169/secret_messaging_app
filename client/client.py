import json
import secrets
import time
from sqlite3 import Connection, Cursor
from crypto.rsa.keygen import get_rsa_key
from crypto.rsa.rsa import RSA
from client.connection import ServerConnection
from client.database import db
from protocol.message import Message
from protocol.message_type import MessageType
from common.config import SERVER_HOST, SERVER_PORT, RSA_KEY_SIZE, RETRY_ATTEMPTS, RETRY_DELAY
from crypto.des.des import DES
from common.utils import int_to_bits
from protocol.hash_helper import hash_values, pre_hash_password

class Client:
    def __init__(self):
        self.conn = None
        self.username = None
        self.private_rsa = None
        db.init_db()

    def load_local_identity(self) -> None:
        connection = db.get_connection()
        cursor = connection.cursor()
        cursor.execute(
            "SELECT username, private_rsa_n, private_rsa_e, private_rsa_d FROM local_identity"
        )
        row = cursor.fetchone()
        connection.close()
        if row:
            self.username = row[0]
            self.private_rsa = RSA(int(row[1]), int(row[2]), int(row[3]))

    def __ensure_connected(self) -> bool:
        if self.conn and self.conn.client_rsa != self.private_rsa:
            try: self.conn.close()
            except: pass
            self.conn = None

        if not self.conn:
            if not self.private_rsa:
                n, e, d = get_rsa_key(RSA_KEY_SIZE)
                self.private_rsa = RSA(n, e, d)

            self.conn = ServerConnection(SERVER_HOST, SERVER_PORT, self.private_rsa)
            try:
                self.conn.connect()
            except Exception as e:
                self.conn = None
                return False
        return True

    def register(self, username: str, password: str) -> tuple[bool, str]:
        db.set_db_path(f"client_{username}.db")
        db.init_db()
        self.username = username

        print("Generating keys (this may take a while)...")
        n, e, d = get_rsa_key(RSA_KEY_SIZE)
        self.private_rsa = RSA(n, e, d)

        c = db.get_connection()
        cursor = c.cursor()
        cursor.execute("INSERT OR REPLACE INTO local_identity VALUES (?, ?, ?, ?)",
                       (username, str(n), str(e), str(d)))
        c.commit()
        c.close()

        if not self.__ensure_connected(): 
            return False, "Connection failed"

        password_prehash = pre_hash_password(password, username)

        msg = Message(MessageType.REGISTER, {
            "username": username,
            "password_hash": password_prehash,
            "client_rsa_pub": {
                "n": n,
                "e": e
            }
        })
        self.conn.send(msg)
        resp = self.conn.receive()
        if resp.type == MessageType.OK:
            return True, "Registration successful!"
        else:
            err = resp.payload.get('error')
            return False, f"Registration failed: {err}"

    def login(self, username: str, password: str) -> tuple[bool, str]:
        db.set_db_path(f"client_{username}.db")
        db.init_db()
        self.load_local_identity()
        if not self.private_rsa:
            return False, "Login failed: No local identity found. You must register on this device first."

        if not self.__ensure_connected(): 
            return False, "Connection failed"

        password_prehash = pre_hash_password(password, username)

        msg = Message(MessageType.LOGIN, {
            "username": username,
            "password_hash": password_prehash
        })
        self.conn.send(msg)
        resp = self.conn.receive()
        if resp.type == MessageType.OK:
            self.username = username
            return True, "Login successful!"
        else:
            err = resp.payload.get('error')
            return False, f"Login failed: {err}"

    def send_secure_message(self, recipient: str, content: str) -> tuple[bool, str]:
        if not self.username: return False, "Not logged in"
        if not self.__ensure_connected(): return False, "Connection failed"

        connection = db.get_connection()
        cursor = connection.cursor()

        attempts = 0
        last_error = ""

        while attempts < RETRY_ATTEMPTS:
            try:
                cursor.execute(
                    "SELECT session_key, public_rsa_n, public_rsa_e FROM users WHERE username=?",
                    (recipient,)
                )

                row = cursor.fetchone()

                session_key_hex = None
                recipient_rsa = None

                if row and row[0]:
                    session_key_hex = row[0]
                else:
                    if row and row[1]:
                        recipient_rsa = RSA(int(row[1]), int(row[2]))
                    else:
                        try:
                            recipient_rsa = self.__get_public_key(recipient, connection, cursor)
                        except Exception as e:
                            return False, str(e)

                    session_key_bits = secrets.randbits(64)
                    keys_bytes = session_key_bits.to_bytes(8, "big")
                    enc_key_blocks = recipient_rsa.encrypt(keys_bytes)

                    key_payload = json.dumps({"type": "KEY", "data": enc_key_blocks})
                    relay_msg = Message(MessageType.SEND_MESSAGE, {
                        "recipient": recipient,
                        "sender": self.username,
                        "ciphertext": key_payload
                    })
                    self.conn.send(relay_msg)
                    resp = self.conn.receive()
                    if resp.type != MessageType.OK:
                        last_error = resp.payload.get('error', "Key relay failed")
                        attempts += 1
                        time.sleep(RETRY_DELAY)
                        continue

                    session_key_hex = keys_bytes.hex()
                    cursor.execute(
                        "UPDATE users SET session_key=? WHERE username=?",
                        (session_key_hex, recipient)
                    )
                    connection.commit()

                des_key = int_to_bits(int.from_bytes(bytes.fromhex(session_key_hex), "big"), 64)
                des = DES(des_key)

                ciphertext = des.encrypt(content)
                msg_payload = json.dumps({"type": "MSG", "data": ciphertext.hex()})

                msg = Message(MessageType.SEND_MESSAGE, {
                    "recipient": recipient,
                    "sender": self.username,
                    "ciphertext": msg_payload
                })
                self.conn.send(msg)
                resp = self.conn.receive()

                if resp.type == MessageType.OK:
                    cursor.execute(
                        "INSERT INTO messages (sender, receiver, plaintext) VALUES (?, ?, ?)",
                        (self.username, recipient, content)
                    )
                    connection.commit()
                    connection.close()
                    return True, "Sent"
                else:
                    last_error = resp.payload.get('error', "Message send failed")
                    attempts += 1
                    if attempts < RETRY_ATTEMPTS:
                        time.sleep(RETRY_DELAY)
                        continue
                    else:
                        connection.close()
                        return False, last_error
            except Exception as e:
                last_error = str(e)
                attempts += 1
                if attempts < RETRY_ATTEMPTS:
                    time.sleep(RETRY_DELAY)
                else:
                    connection.close()
                    return False, last_error

        connection.close()
        return False, last_error

    def __get_public_key(self, recipient: str, connection: Connection, cursor: Cursor) -> RSA:
        msg = Message(MessageType.GET_PUBLIC_KEY, {"username": recipient})
        self.conn.send(msg)
        resp = self.conn.receive()
        if resp.type != MessageType.OK:
            connection.close()
            raise Exception(f"User {recipient} not found")
        pub = resp.payload["client_rsa_pub"]
        cursor.execute(
            "INSERT OR REPLACE INTO users (username, public_rsa_n, public_rsa_e) VALUES (?, ?, ?)",
            (recipient, str(pub["n"]), str(pub["e"]))
        )
        connection.commit()
        return RSA(int(pub["n"]), int(pub["e"]))

    def fetch_and_store_messages(self) -> list[dict]:
        if not self.username or not self.__ensure_connected(): return []

        msg = Message(MessageType.GET_MESSAGES, {"username": self.username})
        self.conn.send(msg)
        resp = self.conn.receive()

        new_msgs = []
        if resp.type == MessageType.OK:
            messages = resp.payload.get("messages", [])
            if not messages: return []

            connection = db.get_connection()
            cursor = connection.cursor()

            for m in messages:
                sender = m['sender']
                raw_ciphertext = m['ciphertext']

                try:
                    payload = json.loads(raw_ciphertext)
                    m_type = payload.get("type")
                    data = payload.get("data")
                    timestamp = m.get('timestamp')

                    if m_type == "KEY":
                        self.__update_key(data, connection, cursor, sender)
                        new_msgs.append({'sender': sender, 'type': 'KEY'})
                        continue

                    if m_type == "MSG":
                        cursor.execute("SELECT id FROM messages WHERE sender=? AND receiver=? AND timestamp=?",
                                       (sender, self.username, timestamp))
                        if cursor.fetchone():
                            continue

                        ciphertext = bytes.fromhex(data)

                        cursor.execute("SELECT session_key FROM users WHERE username=?", (sender,))
                        row = cursor.fetchone()
                        if row and row[0]:
                            session_key_int = int.from_bytes(bytes.fromhex(row[0]), "big")
                            des_key = int_to_bits(session_key_int, 64)
                            des = DES(des_key)
                            plaintext = des.decrypt(ciphertext)
                        else:
                            plaintext = "[No Session Key]"
                    else:
                        plaintext = f"[Unknown Type: {raw_ciphertext[:20]}]"
                except Exception as e:
                    import sys
                    sys.stderr.write(f"Error processing message from {sender}: {e}\n")
                    plaintext = f"[Decryption Error: {sender}]"

                cursor.execute("INSERT INTO messages (sender, receiver, plaintext, timestamp) VALUES (?, ?, ?, ?)",
                               (sender, self.username, plaintext, timestamp))
                new_msgs.append({'sender': sender, 'text': plaintext})

            connection.commit()
            connection.close()
        return new_msgs

    def __update_key(self, data: list[int], connection: Connection, cursor: Cursor, sender: str) -> None:
        key_bytes = self.private_rsa.decrypt(data)
        session_key_hex = key_bytes[-8:].hex()

        cursor.execute("""
            INSERT INTO users (username, session_key) VALUES (?, ?)
            ON CONFLICT(username) DO UPDATE SET session_key=excluded.session_key
        """, (sender, session_key_hex))
        connection.commit()

    def get_local_contacts(self) -> list[dict]:
        c = db.get_connection()
        cursor = c.cursor()
        cursor.execute("SELECT username FROM users")
        contacts = [row[0] for row in cursor.fetchall()]
        c.close()
        return contacts

    def get_local_history(self, contact: str) -> list[dict]:
        c = db.get_connection()
        cursor = c.cursor()
        cursor.execute("""
            SELECT sender, plaintext, timestamp 
            FROM messages 
            WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?)
            ORDER BY timestamp ASC
        """, (self.username, contact, contact, self.username))
        history = cursor.fetchall()
        c.close()
        return history

if __name__ == "__main__":
    from client.gui import App
    client = Client()
    app = App(client)
    app.mainloop()
