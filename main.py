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

def decrypt_message(message, key, nonce):
    aesgcm = AESGCM(key)

    decrypted_message = aesgcm.decrypt(nonce, message, None)

    return decrypted_message

def menu():
    print("Choisissez une option :")
    print("1 - Chiffrer un message")
    print("2 - Déchiffrer un message")
    return input("> ")

choice = menu()

if choice == "1":
    message = input("Entrez le message à chiffrer : ").encode()
    encrypted_message, key, nonce = encrypt_message(message)
    print(f"Message encrypté : {base64.b64encode(encrypted_message).decode()}")
    print(f"Clé : {base64.b64encode(key).decode()}")
    print(f"Nonce : {base64.b64encode(nonce).decode()}")
elif choice == "2":
    message = base64.b64decode(input("Message chiffré : "))
    key = base64.b64decode(input("Clé (Base64): "))
    nonce = base64.b64decode(input("Nonce (Base64) : "))
    decrypted_message = decrypt_message(message, key, nonce)
    print(f"Message décrypté : {decrypted_message.decode()}")