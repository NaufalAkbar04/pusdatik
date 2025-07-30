from flask import Flask, request, jsonify
from flask_cors import CORS
from database import init_db, get_user_by_email, create_user_and_vault, get_encrypted_vault_blob, update_encrypted_vault_blob
import os # Untuk mendapatkan sesi acak sederhana, bukan untuk produksi

app = Flask(__name__)
CORS(app) # Mengizinkan permintaan dari frontend Anda (mis. http://127.0.0.1:5500)

# Inisialisasi database saat aplikasi dimulai
init_db()

# Dummy session management (BUKAN untuk produksi)
sessions = {} # userId -> sessionId
user_session_map = {} # sessionId -> userId

@app.route('/')
def home():
    return "SATRIA Backend is running!"

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    email = data.get('email')
    master_salt_b64 = data.get('masterSalt')
    initial_encrypted_vault_blob = data.get('initialVaultBlob') # Vault kosong yang sudah dienkripsi

    if not email or not master_salt_b64 or initial_encrypted_vault_blob is None:
        return jsonify({"message": "Missing required fields"}), 400

    user_id = create_user_and_vault(email, master_salt_b64, initial_encrypted_vault_blob)
    if user_id:
        return jsonify({"message": "User registered successfully", "userId": user_id}), 201
    else:
        return jsonify({"message": "User already exists"}), 409

@app.route('/login', methods=['POST'])
def login_user():
    data = request.json
    email = data.get('email')

    user = get_user_by_email(email)
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Ambil salt dan blob vault terenkripsi
    master_salt_b64 = user['master_salt']
    encrypted_vault_blob = get_encrypted_vault_blob(user['id'])

    # Di sini, frontend yang akan melakukan verifikasi master password dengan salt yang diberikan.
    # Jika master password cocok, frontend akan mendekripsi vault dan mengirimkan token sesi.

    # Dummy session creation (BUKAN untuk produksi)
    session_id = os.urandom(16).hex()
    sessions[user['id']] = session_id
    user_session_map[session_id] = user['id']

    return jsonify({
        "message": "Login successful (proceed to client-side decryption)",
        "userId": user['id'],
        "masterSalt": master_salt_b64,
        "encryptedVaultBlob": encrypted_vault_blob,
        "sessionId": session_id # Kirim session ID ke frontend
    }), 200

@app.route('/vault', methods=['PUT'])
def update_vault():
    data = request.json
    encrypted_vault_blob = data.get('encryptedVaultBlob')
    session_id = request.headers.get('Authorization') # Ambil dari header

    if not session_id or session_id not in user_session_map:
        return jsonify({"message": "Unauthorized"}), 401

    user_id = user_session_map[session_id]

    if not encrypted_vault_blob:
        return jsonify({"message": "No vault data provided"}), 400

    update_encrypted_vault_blob(user_id, encrypted_vault_blob)
    return jsonify({"message": "Vault updated successfully"}), 200

@app.route('/logout', methods=['POST'])
def logout_user():
    session_id = request.headers.get('Authorization')
    if session_id and session_id in user_session_map:
        user_id = user_session_map.pop(session_id)
        sessions.pop(user_id, None)
    return jsonify({"message": "Logged out"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=5000)