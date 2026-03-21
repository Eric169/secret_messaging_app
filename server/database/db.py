import sqlite3

DB_PATH = "server_data.db"

def get_connection() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)

def init_db() -> None:
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            public_key_n TEXT,
            public_key_e TEXT,
            session_key TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient TEXT NOT NULL,
            sender TEXT NOT NULL,
            ciphertext TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (recipient) REFERENCES users (username),
            FOREIGN KEY (sender) REFERENCES users (username)
        )
    ''')
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
