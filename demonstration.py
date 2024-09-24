from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QTextEdit, QLineEdit, QPushButton, QHBoxLayout, QMessageBox, QComboBox
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
import os
import hashlib
from chacha import chacha20, xchacha20, chacha20poly1305

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
        
        select_layout = QHBoxLayout()

        self.select_enc = QComboBox()
        self.select_enc.addItems([
            "chacha20",
            "xchacha20",
            "chacha20poly1305",
            "chacha20 (own implementation)",
            "xchacha20 (own implementation)",
            "chacha20poly1305 (own implementation)"
        ])
        select_layout.addWidget(self.select_enc)
        self.layout.addLayout(select_layout)

        
        self.setLayout(self.layout)

    def get_key(self):
        key       = self.key.text().encode()
        hash_key  = hashlib.sha256()
        hash_key.update(key)
        return hash_key.digest()
    
    def encrypt_text(self):
        plaintext = self.text_input.toPlainText().encode()
        key       = self.get_key()
        if plaintext:
            res = {}
            enc_type = self.select_enc.currentText()
            if enc_type == "chacha20":
                nonce      = os.urandom(12)
                cipher     = ChaCha20.new(key=key, nonce=nonce)
                ciphertext = cipher.encrypt(plaintext)
            elif enc_type == "xchacha20":
                nonce      = os.urandom(24)
                cipher     = ChaCha20.new(key=key, nonce=nonce)
                ciphertext = cipher.encrypt(plaintext)
            elif enc_type == "chacha20poly1305":
                cipher          = ChaCha20_Poly1305.new(key=key)
                cipher.update(b"header")
                ciphertext, tag = cipher.encrypt_and_digest(plaintext)
                ciphertext      = ciphertext + tag
                nonce           = cipher.nonce
            elif enc_type == "chacha20 (own implementation)":
                nonce      = os.urandom(12)
                cipher     = chacha20.ChaCha20(key, nonce)
                ciphertext = cipher.encrypt(plaintext)
            elif enc_type == "xchacha20 (own implementation)":
                nonce      = os.urandom(24)
                cipher     = xchacha20.XChaCha20(key, nonce)
                ciphertext = cipher.encrypt(plaintext)
            else:
                cipher     = chacha20poly1305.ChaCha20Poly1305(key)
                nonce      = os.urandom(12)
                ciphertext = cipher.encrypt(nonce, plaintext, aad=b"header")


            res["nonce"] = b64encode(nonce).decode('utf-8')
            res["ciphertext"] = b64encode(ciphertext).decode('utf-8')
            result = json.dumps(res)
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

            enc_type = self.select_enc.currentText()
            if enc_type == "chacha20":
                cipher     = ChaCha20.new(key=key, nonce=nonce)
                plaintext  = cipher.decrypt(ciphertext)
            elif enc_type == "xchacha20":
                cipher     = ChaCha20.new(key=key, nonce=nonce)
                plaintext  = cipher.decrypt(ciphertext)
            elif enc_type == "chacha20poly1305":
                cipher    = ChaCha20_Poly1305.new(key=key, nonce=nonce)
                cipher.update(b"header")
                plaintext = cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
            elif enc_type == "chacha20 (own implementation)":
                cipher    = chacha20.ChaCha20(key, nonce)
                plaintext = cipher.decrypt(ciphertext)
            elif enc_type == "xchacha20 (own implementation)":
                cipher    = xchacha20.XChaCha20(key, nonce)
                plaintext = cipher.decrypt(ciphertext)
            else:
                cipher    = chacha20poly1305.ChaCha20Poly1305(key)
                plaintext = cipher.decrypt(nonce, ciphertext, aad=b"header")

            self.text_input.setText(plaintext.decode())
        except (ValueError, KeyError) as e:
            self.show_error_message("Error", f"Incorrect key: {e}")

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
