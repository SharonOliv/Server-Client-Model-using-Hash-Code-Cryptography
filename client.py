import socket
import secrets
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def generate_aes_key(shared_secret):
    """ Derives AES key from shared secret using HKDF. """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)

def hash_message(message):
    """ Returns a SHA-512 hash of the given message. """
    return hashlib.sha512(message.encode()).digest()

def encrypt_message(key, plaintext):
    """ Encrypts the message using AES-CBC with padding and prepends the message hash. """
    msg_hash = hash_message(plaintext)
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(msg_hash + plaintext.encode(), AES.block_size))
    encrypted_b64 = base64.b64encode(iv + ciphertext).decode()
    print(f"[CLIENT] Sending (encrypted, BASE64): {encrypted_b64}")
    return encrypted_b64

def decrypt_message(key, b64_ciphertext):
    """ Decrypts the message using AES-CBC, verifies hash integrity. """
    try:
        raw = base64.b64decode(b64_ciphertext)
        iv, ciphertext = raw[:16], raw[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = unpad(cipher.decrypt(ciphertext), AES.block_size)

        received_hash = decrypted_padded[:64]
        decrypted_text = decrypted_padded[64:].decode()

        if received_hash != hash_message(decrypted_text):
            print("[CLIENT] WARNING: Message integrity compromised!")
            return None

        print(f"[CLIENT] Received (decrypted): {decrypted_text}")
        return decrypted_text
    except Exception as e:
        print(f"[CLIENT] ERROR: Decryption failed - {e}")
        return None

def start_client():
    server_ip = "192.168.0.141"
    server_port = 21312

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_ip, server_port))
    print(f"[CLIENT] Connected to {server_ip}:{server_port}")

    # Receive server's public key
    server_public_bytes = client.recv(1024)
    server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_public_bytes)

    # Generate client's ECDH key pair
    client_private_key = ec.generate_private_key(ec.SECP256R1())
    client_public_key = client_private_key.public_key()
    client_public_bytes = client_public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    # Send client's public key
    client.send(client_public_bytes)

    # Derive shared AES key
    shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
    aes_key = generate_aes_key(shared_secret)
    print(f"[CLIENT] Shared AES Key: {aes_key.hex()}")

    while True:
        msg = input("[CLIENT]: ").strip()
        if not msg:
            continue  # Ignore empty messages

        encrypted_msg = encrypt_message(aes_key, msg)
        client.send(encrypted_msg.encode())

        if msg.lower() == "bye":
            print("[CLIENT] Connection closing...")
            break

        encrypted_reply = client.recv(2048).decode()
        print(f"[CLIENT] Received (encrypted, BASE64): {encrypted_reply}")
        decrypted_reply = decrypt_message(aes_key, encrypted_reply)

        if decrypted_reply is None:
            continue

        if decrypted_reply.lower() == "bye":
            print("[CLIENT] Server ended the conversation. Closing connection...")
            break

    client.close()
    print("[CLIENT] Disconnected.")

if __name__ == "__main__":
    start_client()
