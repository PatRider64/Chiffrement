from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet
import base64
import os
import pathlib
from pathlib import Path

class Home(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Chiffrement de messages et fichiers')
        self.resize(800, 600)
        self.title = QLabel('Chiffrement de messages et fichiers')
        self.title.setStyleSheet("font-size: 24px; font-weight: bold;")
        self.title.setAlignment(Qt.AlignCenter)

        self.encrypt_message_label = QLabel('Encrypter un message')
        self.decrypt_message_label = QLabel('Décrypter un message')
        self.encrypt_file_label = QLabel('Encrypter un fichier')
        self.decrypt_file_label = QLabel('Décrypter un fichier')

        self.message_encrypt_message_label = QLabel('Message à encrypter')
        self.message_encrypt_message_text_box = QLineEdit(self)
        self.message_encrypt_button = QPushButton('Encrypter', self)
        self.message_encrypt_button.clicked.connect(self.encrypt_message)
        self.message_encrypt_result_message_label = QLabel('Message encrypté obtenu')
        self.message_encrypt_result_message_text_box = QLineEdit(self)
        self.message_encrypt_result_key_label = QLabel('Clé obtenue')
        self.message_encrypt_result_key_text_box = QLineEdit(self)
        self.message_encrypt_result_nonce_label = QLabel('Nonce obtenu')
        self.message_encrypt_result_nonce_text_box = QLineEdit(self)

        self.message_decrypt_message_label = QLabel('Message à décrypter')
        self.message_decrypt_key_label = QLabel('Clé à utiliser')
        self.message_decrypt_nonce_label = QLabel('Nonce à utiliser')
        self.message_decrypt_message_text_box = QLineEdit(self)
        self.message_decrypt_key_text_box = QLineEdit(self)
        self.message_decrypt_nonce_text_box = QLineEdit(self)
        self.message_decrypt_button = QPushButton('Décrypter', self)
        self.message_decrypt_button.clicked.connect(self.decrypt_message)
        self.message_decrypt_result_label = QLabel('Message décrypté obtenu')
        self.message_decrypt_result_text_box = QLineEdit(self)

        self.encrypt_file_selector_button = QPushButton('Sélectionner un fichier', self)
        self.encrypt_file_selector_button.clicked.connect(self.open_encrypt_file_selector)
        self.encrypt_file_path_box = QLineEdit(self)
        self.encrypt_file_path_box.setEnabled(False)
        self.encrypt_file_button = QPushButton('Encrypter le fichier', self)
        self.encrypt_file_button.clicked.connect(self.encrypt_file)
        self.encrypt_file_key_label = QLabel('Clé obtenue après chiffrement du fichier')
        self.encrypt_file_key_text_box = QLineEdit(self)

        self.decrypt_file_selector_button = QPushButton('Sélectionner un fichier', self)
        self.decrypt_file_selector_button.clicked.connect(self.open_decrypt_file_selector)
        self.decrypt_file_path_box = QLineEdit(self)
        self.decrypt_file_path_box.setEnabled(False)
        self.decrypt_file_button = QPushButton('Décrypter le fichier', self)
        self.decrypt_file_button.clicked.connect(self.decrypt_file)
        self.decrypt_file_key_label = QLabel('Clé à utiliser pour le déchiffrement du fichier')
        self.decrypt_file_key_text_box = QLineEdit(self)

        self.master = QVBoxLayout()

        encrypt_message_layout = QHBoxLayout()
        decrypt_message_layout = QHBoxLayout()
        encrypt_file_layout = QHBoxLayout()
        decrypt_file_layout = QHBoxLayout()

        self.master.addWidget(self.title)

        encrypt_message_layout.addWidget(self.encrypt_message_label)
        encrypt_message_layout.addWidget(self.message_encrypt_message_text_box)
        encrypt_message_layout.addWidget(self.message_encrypt_button)
        encrypt_message_layout.addWidget(self.message_encrypt_result_message_label)
        encrypt_message_layout.addWidget(self.message_encrypt_result_message_text_box)
        encrypt_message_layout.addWidget(self.message_encrypt_result_key_label)
        encrypt_message_layout.addWidget(self.message_encrypt_result_key_text_box)
        encrypt_message_layout.addWidget(self.message_encrypt_result_nonce_label)
        encrypt_message_layout.addWidget(self.message_encrypt_result_nonce_text_box)

        decrypt_message_layout.addWidget(self.decrypt_message_label)
        decrypt_message_layout.addWidget(self.message_decrypt_message_label)
        decrypt_message_layout.addWidget(self.message_decrypt_message_text_box)
        decrypt_message_layout.addWidget(self.message_decrypt_key_label)
        decrypt_message_layout.addWidget(self.message_decrypt_key_text_box)
        decrypt_message_layout.addWidget(self.message_decrypt_nonce_label)
        decrypt_message_layout.addWidget(self.message_decrypt_nonce_text_box)
        decrypt_message_layout.addWidget(self.message_decrypt_button)
        decrypt_message_layout.addWidget(self.message_decrypt_result_label)
        decrypt_message_layout.addWidget(self.message_decrypt_result_text_box)

        encrypt_file_layout.addWidget(self.encrypt_file_label)
        encrypt_file_layout.addWidget(self.encrypt_file_selector_button)
        encrypt_file_layout.addWidget(self.encrypt_file_path_box)
        encrypt_file_layout.addWidget(self.encrypt_file_button)
        encrypt_file_layout.addWidget(self.encrypt_file_key_label)
        encrypt_file_layout.addWidget(self.encrypt_file_key_text_box)

        decrypt_file_layout.addWidget(self.decrypt_file_label)
        decrypt_file_layout.addWidget(self.decrypt_file_selector_button)
        encrypt_file_layout.addWidget(self.decrypt_file_path_box)
        decrypt_file_layout.addWidget(self.decrypt_file_button)
        decrypt_file_layout.addWidget(self.decrypt_file_key_label)
        decrypt_file_layout.addWidget(self.decrypt_file_key_text_box)

        self.master.addLayout(encrypt_message_layout)
        self.master.addLayout(decrypt_message_layout)
        self.master.addLayout(encrypt_file_layout)
        self.master.addLayout(decrypt_file_layout)

        self.setLayout(self.master)
        self.show()

    def open_encrypt_file_selector(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select File')
        if file_path:
            self.encrypt_file_path_box.setText(file_path)

    def open_decrypt_file_selector(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select File')
        if file_path:
            self.decrypt_file_path_box.setText(file_path)

    def encrypt_message(self):
        message = self.message_encrypt_message_text_box.text().encode()
        key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)

        encrypted_message = aesgcm.encrypt(nonce, message, None)
        self.message_encrypt_result_message_text_box.setText(base64.b64encode(encrypted_message).decode())
        self.message_encrypt_result_key_text_box.setText(base64.b64encode(key).decode())
        self.message_encrypt_result_nonce_text_box.setText(base64.b64encode(nonce).decode())

    def decrypt_message(self):
        message = base64.b64decode(self.message_decrypt_message_text_box.text())
        key = base64.b64decode(self.message_decrypt_key_text_box.text())
        nonce = base64.b64decode(self.message_decrypt_nonce_text_box.text())
        aesgcm = AESGCM(key)

        decrypted_message = aesgcm.decrypt(nonce, message, None)

        self.message_decrypt_result_text_box.setText(decrypted_message.decode())

    def encrypt_file(self):
        path_file = self.encrypt_file_path_box.text()
        filename = Path(path_file).resolve()
        key = Fernet.generate_key()
        f = Fernet(key)

        try:
            with open(filename, "rb") as file:
                file_data = file.read()
                encrypted_data = f.encrypt(file_data)
        except Exception as e:
            error_msg = QMessageBox()
            error_msg.setIcon(QMessageBox.Warning)
            error_msg.setText(f"Erreur lors de la lecture ou du chiffrement du fichier : {e}")
            error_msg.setWindowTitle("Erreur")
            retval = error_msg.exec_()
            return

        encrypted_file_path = str(Path.home()) + r"\Downloads\\" + os.path.basename(path_file) + ".encrypted"

        try:
            with open(encrypted_file_path, "wb") as encrypted_file:
                encrypted_file.write(encrypted_data)
        except Exception as e:
            error_msg = QMessageBox()
            error_msg.setIcon(QMessageBox.Warning)
            error_msg.setText(f"Erreur lors de l'écriture du fichier chiffré : {e}")
            error_msg.setWindowTitle("Erreur")
            retval = error_msg.exec_()
            return

        self.encrypt_file_key_text_box.setText(base64.b64encode(key).decode())
        success_msg = QMessageBox()
        success_msg.setIcon(QMessageBox.Information)
        success_msg.setText("Votre fichier chiffré est maintenant téléchargé!")
        success_msg.setWindowTitle("Succès")
        retval = success_msg.exec_()

    def decrypt_file(self):
        path_file = self.decrypt_file_path_box.text()
        key = base64.b64decode(self.decrypt_file_key_text_box.text())

        if pathlib.Path(path_file).suffix != ".encrypted":
            error_msg = QMessageBox()
            error_msg.setIcon(QMessageBox.Warning)
            error_msg.setText(f"Erreur: Le fichier doit être un fichier ENCRYPTED")
            error_msg.setWindowTitle("Erreur")
            retval = error_msg.exec_()
            return

        filename = Path(path_file).resolve()
        f = Fernet(key)

        try:
            with open(filename, "rb") as encrypt_file:
                encrypted_data = encrypt_file.read()
                decrypted_data = f.decrypt(encrypted_data)
        except Exception as e:
            error_msg = QMessageBox()
            error_msg.setIcon(QMessageBox.Warning)
            error_msg.setText(f"Erreur lors de la lecture du fichier : {e}")
            error_msg.setWindowTitle("Erreur")
            retval = error_msg.exec_()
            return

        decrypted_file_path = str(Path.home()) + r"\Downloads\\" + os.path.basename(path_file).removesuffix(".encrypted")

        try:
            with open(decrypted_file_path, "wb") as decrypted_file:
                decrypted_file.write(decrypted_data)
        except Exception as e:
            error_msg = QMessageBox()
            error_msg.setIcon(QMessageBox.Warning)
            error_msg.setText(f"Erreur lors du déchiffrement du fichier : {e}")
            error_msg.setWindowTitle("Erreur")
            retval = error_msg.exec_()
            return

        success_msg = QMessageBox()
        success_msg.setIcon(QMessageBox.Information)
        success_msg.setText("Votre fichier déchiffré est maintenant téléchargé!")
        success_msg.setWindowTitle("Succès")
        retval = success_msg.exec_()

if __name__ == "__main__":
    app = QApplication([])
    main = Home()
    main.show()
    app.exec_()
