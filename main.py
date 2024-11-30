from flask import Flask, request, jsonify, render_template, session
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

app = Flask(__name__)  # Corrected here
app.secret_key = os.urandom(24)  # Untuk session management

# Helper functions
def generate_keys(key_size):
    """Generate RSA keys."""
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_message(message, pub_key):
    """Encrypts a message using the public key."""
    recipient_key = RSA.import_key(pub_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_message = cipher_rsa.encrypt(message.encode("utf-8"))
    return base64.b64encode(encrypted_message).decode("utf-8")

def decrypt_message(ciphertext, priv_key):
    """Decrypts a ciphertext using the private key."""
    private_key = RSA.import_key(priv_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decoded_message = base64.b64decode(ciphertext)
    decrypted_message = cipher_rsa.decrypt(decoded_message)
    return decrypted_message.decode("utf-8")

# Routes
@app.route('/')
def index():
    """Render the main page."""
    return render_template("index.html")

@app.route('/generate_keys', methods=['POST'])
def generate_keys_route():
    """Generate RSA keys with the specified size."""
    data = request.json
    key_size = int(data.get("key_size", 2048))  # Default to 2048-bit keys
    private_key, public_key = generate_keys(key_size)
    
    # Store keys in the session
    session['private_key'] = private_key.decode("utf-8")
    session['public_key'] = public_key.decode("utf-8")
    
    return jsonify({
        "private_key": session['private_key'],
        "public_key": session['public_key']
    })

@app.route('/encrypt', methods=['POST'])
def encrypt():
    """Encrypt a message using the public key."""
    if 'public_key' not in session:
        return jsonify({"error": "Generate keys first!"}), 400

    data = request.json
    message = data.get("message")
    if not message:
        return jsonify({"error": "No message provided"}), 400

    encrypted_message = encrypt_message(message, session['public_key'])
    return jsonify({"encrypted_message": encrypted_message})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Decrypt a message using the private key."""
    if 'private_key' not in session:
        return jsonify({"error": "Generate keys first!"}), 400

    data = request.json
    ciphertext = data.get("ciphertext")
    if not ciphertext:
        return jsonify({"error": "No ciphertext provided"}), 400

    decrypted_message = decrypt_message(ciphertext, session['private_key'])
    return jsonify({"decrypted_message": decrypted_message})

if __name__ == "__main__":  # Corrected here as well
    app.run(debug=True)
