from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QLabel, QTextEdit, QLineEdit, QPushButton, QHBoxLayout, QMessageBox, QComboBox, QPushButton, QFileDialog, QTabWidget, QWidget, QSizePolicy
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20, ChaCha20_Poly1305
import os
import hashlib
from chacha import chacha20, xchacha20, chacha20poly1305
import struct
from functools import partial

class EncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encryption/Decryption App")
        
        self.setCentralWidget(InputEnc(self))
        
class InputEnc(QWidget):
    def __init__(self, parent):
        super(QWidget, self).__init__(parent)

        self.lay = QVBoxLayout(self)

        self.tabs = QTabWidget()
        self.tab1 = QWidget()
        self.tab2 = QWidget()

        self.lay.addWidget(self.tabs)

        self.tabs.addTab(self.tab1,"Inputs")
        self.tabs.addTab(self.tab2,"Files")

        self.layout = QVBoxLayout(self)

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
        self.lay.addWidget(self.key_label)
        self.key = QLineEdit()
        self.lay.addWidget(self.key)
        
        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton("Encrypt")
        self.encrypt_button.clicked.connect(self.encrypt_text)
        button_layout.addWidget(self.encrypt_button)
        
        self.decrypt_button = QPushButton("Decrypt")
        self.decrypt_button.clicked.connect(self.decrypt_text)
        button_layout.addWidget(self.decrypt_button)

        self.lay.addLayout(button_layout)
        
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
        self.lay.addLayout(select_layout)

        self.tab1.layout = self.layout
        self.tab1.setLayout(self.tab1.layout)


        self.layout1 = QVBoxLayout(self)

        self.input_label1 = QLabel("Input File:")
        self.input_label1.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.layout1.addWidget(self.input_label1)
        self.in_file1 = QLabel("None")
        self.in_file1.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.layout1.addWidget(self.in_file1)

        in_file_layout1 = QHBoxLayout()

        self.input_load_btn1 = QPushButton('Load from file')
        self.input_load_btn1.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.input_load_btn1.clicked.connect(partial(self.read_file, self.in_file1, False))
        in_file_layout1.addWidget(self.input_load_btn1)

        self.layout1.addLayout(in_file_layout1)

        self.out_label1 = QLabel("Output File:")
        self.out_label1.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.layout1.addWidget(self.out_label1)
        self.out_file1 = QLabel("None")
        self.out_file1.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.layout1.addWidget(self.out_file1)

        out_file_layout1 = QHBoxLayout()

        self.out_load_btn1 = QPushButton('Save to file')
        self.out_load_btn1.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.out_load_btn1.clicked.connect(partial(self.read_file, self.out_file1, True))
        out_file_layout1.addWidget(self.out_load_btn1)

        self.layout1.addLayout(out_file_layout1)

        filler = QLabel("")
        self.layout1.addWidget(filler)

        self.tab2.layout = self.layout1
        self.tab2.setLayout(self.tab2.layout)
        
        self.setLayout(self.lay)

    def read_file(self, label, saver):
        if saver:
            file = self.show_file_saver_dialog()
        else:
            file = self.show_file_picker_dialog()
        if file:
            label.setText(file)

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
        fileName, _ = QFileDialog.getSaveFileName(self, "Save File", "", "All Files (*);;Text Files (*.txt)", options=options)
        return fileName


    def get_key(self):
        key       = self.key.text().encode()
        hash_key  = hashlib.sha256()
        hash_key.update(key)
        return hash_key.digest()
    
    def encrypt_text(self):
        if self.tabs.currentIndex() == 0:
            plaintext = self.text_input.toPlainText().encode()
        else:
            try:
                if not self.in_file1.text() == "None" and not self.out_file1.text() == "None":
                    with open(self.in_file1.text(), 'rb') as file:
                        plaintext = file.read()
                else:
                    return
            except Exception as e:
                self.show_error_message("Error", f"Failed loading file: {e}")


        key = self.get_key()
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

            if self.tabs.currentIndex() == 0:
                res["nonce"] = b64encode(nonce).decode('utf-8')
                res["ciphertext"] = b64encode(ciphertext).decode('utf-8')
                result = json.dumps(res)
                self.text_output.setText(result)
            else:
                with open(self.out_file1.text(), 'wb') as file:
                    file.write(struct.pack('B', len(nonce)))
                    file.write(nonce)
                    file.write(ciphertext)
        else:
            self.show_error_message("Error", "Input must not be empty!")
 
    def decrypt_text(self):
        key = self.get_key()
        try:
            if self.tabs.currentIndex() == 0:
                json_input = self.text_output.toPlainText().encode()
                b64        = json.loads(json_input)
                nonce      = b64decode(b64['nonce'])
                ciphertext = b64decode(b64['ciphertext'])
            else:
                if not self.in_file1.text() == "None" and not self.out_file1.text() == "None":
                    with open(self.in_file1.text(), 'rb') as file:
                        data = file.read(1)
                        nonce_len = int(struct.unpack('B', data)[0])
                        nonce = file.read(nonce_len)
                        ciphertext = file.read()
                else:
                    return

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

            if self.tabs.currentIndex() == 0:
                self.text_input.setText(plaintext.decode())
            else:
                with open(self.out_file1.text(), 'wb') as file:
                    file.write(plaintext)
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
