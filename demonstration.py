from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QTextEdit, QLineEdit, QPushButton, QHBoxLayout, QMessageBox
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20
import os
import hashlib

class EncryptionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encryption/Decryption App")
        
        self.layout = QVBoxLayout()
        
        self.input_label = QLabel("Input:")
        self.layout.addWidget(self.input_label)
        
        self.text_input = QTextEdit()
        self.layout.addWidget(self.text_input)

        self.output_label = QLabel("Output:")
        self.layout.addWidget(self.output_label)
        
        self.text_output = QTextEdit()
        self.layout.addWidget(self.text_output)

        self.key_label = QLabel("Key:")
        self.layout.addWidget(self.key_label)
        self.key = QLineEdit()
        self.layout.addWidget(self.key)
        
        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Encrypt")
        self.encrypt_button.clicked.connect(self.encrypt_text)
        button_layout.addWidget(self.encrypt_button)
        
        self.decrypt_button = QPushButton("Decrypt")
        self.decrypt_button.clicked.connect(self.decrypt_text)
        button_layout.addWidget(self.decrypt_button)

        self.layout.addLayout(button_layout)
        
        self.setLayout(self.layout)

    def get_key(self):
        key       = self.key.text().encode()
        hash_key  = hashlib.sha256()
        hash_key.update(key)
        return hash_key.digest()
    
    def encrypt_text(self):
        plaintext = self.text_input.toPlainText().encode()
        print(plaintext[0])
        key       = self.get_key()
        if plaintext:
            nonce      = os.urandom(12)
            cipher     = ChaCha20.new(key=key, nonce=nonce)
            ciphertext = cipher.encrypt(plaintext)
            nonce_b64  = b64encode(nonce).decode('utf-8')
            ct_b64     = b64encode(ciphertext).decode('utf-8')
            result     = json.dumps({'nonce': nonce_b64, 'ciphertext': ct_b64})
            self.text_output.setText(result)
        else:
            self.show_error_message("Error", "Input must not be empty!")
 
    def decrypt_text(self):
        key = self.get_key()
        try:
            json_input = self.text_output.toPlainText().encode()
            b64        = json.loads(json_input)
            nonce      = b64decode(b64['nonce'])
            ciphertext = b64decode(b64['ciphertext'])
            cipher     = ChaCha20.new(key=key, nonce=nonce)
            plaintext  = cipher.decrypt(ciphertext)
            self.text_input.setText(plaintext.decode())
        except (ValueError, KeyError) as e:
            self.show_error_message("Error", "Incorrect key:")

    def show_error_message(self, title, message):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.exec()

if __name__ == "__main__":
    app = QApplication([])
    window = EncryptionApp()
    window.show()
    app.exec_()
