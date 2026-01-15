from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet
import base64
import os
import pathlib
from pathlib import Path

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

def encrypt_file(path_file):
    filename = Path(path_file).resolve()
    key = Fernet.generate_key()
    f = Fernet(key)

    try:
        with open(filename, "rb") as file:
            file_data = file.read()
            encrypted_data = f.encrypt(file_data)
    except Exception as e:
        print(f"Erreur lors de la lecture ou du chiffrement du fichier : {e}")
        return

    encrypted_file_path = str(Path.home()) + r"\Downloads\\" + os.path.basename(path_file) + ".encrypted"

    try:
        with open(encrypted_file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)
    except Exception as e:
        print(f"Erreur lors de l'écriture du fichier chiffré : {e}")
        return

    return key

def decrypt_file(path_file, key):
    if pathlib.Path(path_file).suffix != ".encrypted":
        print("Erreur: Le fichier doit être un fichier ENCRYPTED")
        return
    
    filename = Path(path_file).resolve()
    f = Fernet(key)

    try:
        with open(filename, "rb") as encrypt_file:
            encrypted_data = encrypt_file.read()
            decrypted_data = f.decrypt(encrypted_data)
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier : {e}")
        return

    decrypted_file_path = str(Path.home()) + r"\Downloads\\" + os.path.basename(path_file).removesuffix(".encrypted")

    try:
        with open(decrypted_file_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)
    except Exception as e:
        print(f"Erreur lors du déchiffrement du fichier : {e}")
        return
    
    print("Votre fichier déchiffré est maintenant téléchargé.")

def main_menu():
    print("Choisissez une option :")
    print("1 - Message")
    print("2 - Fichier")
    return input("> ")

def message_menu():
    print("Choisissez une option :")
    print("1 - Chiffrer un message")
    print("2 - Déchiffrer un message")
    return input("> ")

def file_menu():
    print("Choisissez une option :")
    print("1 - Chiffrer un fichier")
    print("2 - Déchiffrer un fichier")
    return input("> ")

choice = main_menu()

if choice == "1":
    message_choice = message_menu()

    if message_choice == "1":
        message = input("Entrez le message à chiffrer : ").encode()
        encrypted_message, key, nonce = encrypt_message(message)
        print(f"Message encrypté : {base64.b64encode(encrypted_message).decode()}")
        print(f"Clé : {base64.b64encode(key).decode()}")
        print(f"Nonce : {base64.b64encode(nonce).decode()}")
    elif message_choice == "2":
        message = base64.b64decode(input("Message chiffré : "))
        key = base64.b64decode(input("Clé (Base64): "))
        nonce = base64.b64decode(input("Nonce (Base64) : "))
        decrypted_message = decrypt_message(message, key, nonce)
        print(f"Message décrypté : {decrypted_message.decode()}")
elif choice == "2":
    file_choice = file_menu()

    if file_choice == "1":
        path_file = input("Entrez le chemin du fichier à chiffrer : ")
        key = encrypt_file(path_file)

        if key:
            print(f"Clé : {base64.b64encode(key).decode()}")
            print("Votre fichier chiffré est maintenant téléchargé.")
    elif file_choice == "2":
        path_file = input("Chemin du fichier encrypté : ")
        key = base64.b64decode(input("Clé : "))
        decrypt_file(path_file, key)
