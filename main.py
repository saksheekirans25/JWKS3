import json
from argon2 import PasswordHasher
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import uuid
import hashlib
import os
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from flask import Flask

def create_app():
    app = Flask(__name__)
    # Add routes or configurations here
    return app

# Load environment variables from .env file
load_dotenv()

app = create_app()

# Initialize rate limiter
limiter = Limiter(get_remote_address, app=app)

# Environment variables
AES_KEY = os.getenv("NOT_MY_KEY")
DB_PATH = 'totally_not_my_privateKeys.db'

# Validate AES key
if not AES_KEY or len(AES_KEY) not in {16, 24, 32}:
    raise ValueError("AES key must be set in 'NOT_MY_KEY' environment variable and be 16, 24, or 32 bytes long.")
AES_KEY = AES_KEY.encode()  # Ensure key is in bytes

# Database connection
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# AES encryption and decryption
def encrypt_data(data):
    key = AES_KEY.ljust(32, b'\0')[:32]
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_data = data + (16 - len(data) % 16) * b' '
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_data(encrypted_data):
    key = AES_KEY.ljust(32, b'\0')[:32]
    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return decrypted_data.rstrip(b' ')

# User Registration
@app.route('/register', methods=['POST'])
def register_user():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')

        if not username or not email:
            return jsonify({"error": "Username and email are required"}), 400

        password = str(uuid.uuid4())
        password_hash = PasswordHasher().hash(password)

        conn = get_db_connection()
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password_hash TEXT NOT NULL,
                            email TEXT UNIQUE,
                            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_login TIMESTAMP)''')
        conn.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                     (username, password_hash, email))
        conn.commit()
        conn.close()

        return jsonify({"password": password}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Store Private Key
@app.route('/store_private_key', methods=['POST'])
def store_private_key():
    try:
        data = request.get_json()
        private_key = data.get("private_key")

        if not private_key:
            return jsonify({"error": "Private key is required"}), 400

        encrypted_key = encrypt_data(private_key.encode())
        conn = get_db_connection()
        conn.execute('''CREATE TABLE IF NOT EXISTS keys (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            private_key BLOB NOT NULL)''')
        conn.execute('INSERT INTO keys (private_key) VALUES (?)', (encrypted_key,))
        conn.commit()
        conn.close()

        return jsonify({"message": "Private key stored securely."}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Retrieve Private Key
@app.route('/get_private_key', methods=['GET'])
def retrieve_private_key():
    try:
        conn = get_db_connection()
        row = conn.execute('SELECT private_key FROM keys ORDER BY id DESC LIMIT 1').fetchone()
        conn.close()

        if not row:
            return jsonify({"error": "Private key not found"}), 404

        private_key = decrypt_data(row['private_key']).decode()
        return jsonify({"private_key": private_key}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Retrieve JWKS
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "48",
                "alg": "RS256",
                "use": "sig",
                "n": "your-modulus",
                "e": "your-exponent"
            }
        ]
    }
    return jsonify(jwks)

# Authentication
@app.route('/auth', methods=['POST'])
@limiter.limit("10 per second")
def auth():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        conn = get_db_connection()
        row = conn.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if not row or not PasswordHasher().verify(row['password_hash'], password):
            return jsonify({"message": "Invalid credentials"}), 401

        log_auth_request(row['id'], request.remote_addr)
        return jsonify({"message": "Authentication successful"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Log Auth Request
def log_auth_request(user_id, ip_address):
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS auth_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        request_ip TEXT NOT NULL,
                        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        user_id INTEGER,
                        FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.execute('INSERT INTO auth_logs (request_ip, request_timestamp, user_id) VALUES (?, ?, ?)',
                 (ip_address, datetime.now(), user_id))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
