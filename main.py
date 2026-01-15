from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import sys

def encrypt_message(message):
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)

    encrypted_message = aesgcm.encrypt(nonce, message, None)

    return encrypted_message, key, nonce

message = sys.argv[1]
encrypted_message, key, nonce = encrypt_message(message.encode())
print(f"Message encrypté : {base64.b64encode(encrypted_message).decode()}")
print(f"Clé : {base64.b64encode(key).decode()}")
print(f"Nonce : {base64.b64encode(nonce).decode()}")