import sqlite3
import os

DATABASE_FILE = 'vault.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row # Mengembalikan baris sebagai objek mirip dictionary
    return conn

def init_db():
    if not os.path.exists(DATABASE_FILE):
        print(f"Creating new database: {DATABASE_FILE}")
    else:
        print(f"Database already exists: {DATABASE_FILE}")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            master_salt TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL -- Dalam aplikasi nyata, ini bisa jadi username
        )
    ''')
    # Catatan: Data brankas (situs, username, password terenkripsi)
    # akan disimpan sebagai satu BLOB terenkripsi di baris ini
    # untuk memastikan arsitektur zero-knowledge.
    # Namun, karena ini demo, kita akan simpan di `users`
    # Ini BUKAN praktik terbaik untuk vault sungguhan, tapi untuk demo Flask
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vault_data (
            user_id INTEGER PRIMARY KEY,
            encrypted_vault_blob TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized.")

def create_user_and_vault(email, master_salt_b64, initial_encrypted_vault_blob):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (email, master_salt) VALUES (?, ?)", (email, master_salt_b64))
        user_id = cursor.lastrowid
        cursor.execute("INSERT INTO vault_data (user_id, encrypted_vault_blob) VALUES (?, ?)", (user_id, initial_encrypted_vault_blob))
        conn.commit()
        return user_id
    except sqlite3.IntegrityError:
        print(f"User with email {email} already exists.")
        return None
    finally:
        conn.close()

def get_user_by_email(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, master_salt FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_encrypted_vault_blob(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_vault_blob FROM vault_data WHERE user_id = ?", (user_id,))
    blob = cursor.fetchone()
    conn.close()
    return blob['encrypted_vault_blob'] if blob else None

def update_encrypted_vault_blob(user_id, new_blob):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE vault_data SET encrypted_vault_blob = ? WHERE user_id = ?", (new_blob, user_id))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()