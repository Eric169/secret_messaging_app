import sqlite3
import os

DB_DIR = "client/dbs"
DB_FILENAME = os.path.join(DB_DIR, "client_data.db")

def set_db_path(filename):
    global DB_FILENAME
    if not filename.startswith(DB_DIR):
        DB_FILENAME = os.path.join(DB_DIR, filename)
    else:
        DB_FILENAME = filename

def get_connection():
    return sqlite3.connect(DB_FILENAME)

def init_db():
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)
    conn = get_connection()

    cursor = conn.cursor()
    
    # Peer users table: username, public_rsa_n, public_rsa_e, session_key
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            public_rsa_n TEXT,
            public_rsa_e TEXT,
            session_key TEXT
        )
    ''')
    
    # Messages table: sender, receiver, plaintext, timestamp
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            plaintext TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Local identity table: username, private_rsa_n, private_rsa_e, private_rsa_d
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS local_identity (
            username TEXT PRIMARY KEY,
            private_rsa_n TEXT,
            private_rsa_e TEXT,
            private_rsa_d TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
