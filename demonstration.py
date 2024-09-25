from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QTextEdit, QLineEdit, QPushButton, QHBoxLayout, QMessageBox, QComboBox, QPushButton, QFileDialog
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
import os
import hashlib
from chacha import chacha20, xchacha20, chacha20poly1305
import struct

class EncryptionApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encryption/Decryption App")
        
        self.layout = QVBoxLayout()
        
        self.input_label = QLabel("Input:")
        self.layout.addWidget(self.input_label)

        in_file_layout = QHBoxLayout()

        self.input_load_btn = QPushButton('Load from file')
        self.input_load_btn.clicked.connect(self.read_input_file)
        in_file_layout.addWidget(self.input_load_btn)

        self.input_save_btn = QPushButton('Save to file')
        self.input_save_btn.clicked.connect(self.write_input_file)
        in_file_layout.addWidget(self.input_save_btn)

        self.layout.addLayout(in_file_layout)
        
        self.text_input = QTextEdit()
        self.layout.addWidget(self.text_input)

        self.output_label = QLabel("Output:")
        self.layout.addWidget(self.output_label)

        out_file_layout = QHBoxLayout()

        self.output_load_btn = QPushButton('Load from file')
        self.output_load_btn.clicked.connect(self.read_out_file)
        out_file_layout.addWidget(self.output_load_btn)

        self.output_save_btn = QPushButton('Save to file')
        self.output_save_btn.clicked.connect(self.write_out_file)
        out_file_layout.addWidget(self.output_save_btn)
        
        self.layout.addLayout(out_file_layout)
        
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

    def read_input_file(self):
        file = self.show_file_picker_dialog()
        if file:
            try:
                with open(file, 'r') as file:
                    # Read the entire contents of the file
                    content = file.read()
                    self.text_input.setText(content)
            except Exception as e:
                self.show_error_message("Error", f"Failed loading file: {e}")

    def write_input_file(self):
        file = self.show_file_saver_dialog()
        if file:
            try:
                with open(file, 'w') as file:
                    plaintext = self.text_input.toPlainText()
                    file.write(plaintext)
            except Exception as e:
                self.show_error_message("Error", f"Failed writing to file: {e}")

    def read_out_file(self):
        file = self.show_file_picker_dialog()
        if file:
            try:
                with open(file, 'rb') as file:
                    data = file.read(1)
                    nonce_len = int(struct.unpack('B', data)[0])
                    nonce = file.read(nonce_len)
                    ciphertext = file.read()

                res = {"nonce": b64encode(nonce).decode('utf-8'), "ciphertext": b64encode(ciphertext).decode('utf-8')}
                result = json.dumps(res)
                self.text_output.setText(result)
            except Exception as e:
                self.show_error_message("Error", f"Failed loading file: {e}")

    def write_out_file(self):
        file = self.show_file_saver_dialog()
        if file:
            try:
                json_input = self.text_output.toPlainText().encode()
                b64        = json.loads(json_input)
                nonce      = b64decode(b64['nonce'])
                ciphertext = b64decode(b64['ciphertext'])
            except Exception as e:
                self.show_error_message("Error", f"No output to save")

            try:
                with open(file, 'wb') as file:
                    file.write(struct.pack('B', len(nonce)))
                    file.write(nonce)
                    file.write(ciphertext)
            except Exception as e:
                self.show_error_message("Error", f"Failed writing to file: {e}")
            

    def show_file_picker_dialog(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Files (*);;Text Files (*.txt)", options=options)
        return fileName

    def show_file_saver_dialog(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getSaveFileName(self, "Save File", "", "Text Files (*.txt);;All Files (*)", options=options)
        return fileName


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
