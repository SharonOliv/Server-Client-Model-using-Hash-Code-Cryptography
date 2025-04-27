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
    print(f"[SERVER] Sending (encrypted, BASE64): {encrypted_b64}")
    return encrypted_b64

def decrypt_message(key, b64_ciphertext):
    """ Decrypts the message using AES-CBC, verifies hash integrity. """
    raw = base64.b64decode(b64_ciphertext)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    received_hash = decrypted_padded[:64]
    decrypted_text = decrypted_padded[64:].decode()

    if received_hash != hash_message(decrypted_text):
        print("[SERVER] WARNING: Message integrity compromised!")
        return None

    print(f"[SERVER] Received (decrypted): {decrypted_text}")
    return decrypted_text

def main():
    server_ip = "192.168.0.141"
    server_port = 21312

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(1)
    print(f"[SERVER] Listening on {server_ip}:{server_port}...")

    try:
        conn, addr = server_socket.accept()
        print(f"[SERVER] Connection established with {addr}")

        # Generate ECDH Key Pair
        server_private_key = ec.generate_private_key(ec.SECP256R1())
        server_public_key = server_private_key.public_key()
        server_public_bytes = server_public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

        # Send server's public key
        conn.send(server_public_bytes)

        # Receive client's public key
        client_public_bytes = conn.recv(1024)
        client_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_public_bytes)

        # Derive Shared AES Key
        shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
        aes_key = generate_aes_key(shared_secret)
        print(f"[SERVER] Shared AES Key: {aes_key.hex()}")

        while True:
            encrypted_message = conn.recv(2048).decode()
            if not encrypted_message or encrypted_message.lower() == "bye":
                print("[SERVER] Client disconnected.")
                break

            print(f"[SERVER] Received (encrypted, BASE64): {encrypted_message}")

            decrypted_message = decrypt_message(aes_key, encrypted_message)
            if decrypted_message:
                print(f"[CLIENT]: {decrypted_message}")

            server_message = input("[SERVER]: ")
            encrypted_response = encrypt_message(aes_key, server_message)

            print(f"[SERVER] Sending (plaintext): {server_message}")
            print(f"[SERVER] Sending (encrypted, BASE64): {encrypted_response}")

            conn.send(encrypted_response.encode())

            if server_message.lower() == "bye":
                print("[SERVER] Closing connection...")
                break

    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down.")
    finally:
        conn.close()
        server_socket.close()
        print("[SERVER] Server socket closed.")

if __name__ == "__main__":
    main()
