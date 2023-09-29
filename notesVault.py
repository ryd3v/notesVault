# -----------------------------------------------------------------------------
# Copyright (C) 2023 Ryan Collins
#
# Author: Ryan Collins
# Email: hello@ryd3v
# Social: @ryd3v
# Version: 4.0.1
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# -----------------------------------------------------------------------------
"""The software is provided "as is", without any guarantee of any kind, express or implied. This includes,
but is not limited to, the warranties of merchantability, fitness for a particular purpose, and noninfringement. The
authors or copyright holders bear no liability for any claims, damages, or other liabilities that may arise,
whether in an action of contract, tort, or otherwise, from, in connection with, or in relation to the software,
its use, or other dealings with the software."""

import base64
import os
import sys
import logging
import qdarktheme
from PyQt6.QtCore import QSize
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton, QInputDialog, \
    QLineEdit, QTextBrowser, QFileDialog, QSizePolicy, QSpacerItem, QMessageBox
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from markdown import markdown


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


def derive_master_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=650000,
        backend=default_backend()
    )
    return kdf.derive(password)


def generate_db_encryption_key() -> bytes:
    return os.urandom(32)  # 256 bits


def encrypt_key(db_key: bytes, master_key: bytes) -> bytes:
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, db_key, None)


def decrypt_key(encrypted_db_key: bytes, master_key: bytes) -> bytes:
    aesgcm = AESGCM(master_key)
    nonce, ct = encrypted_db_key[:12], encrypted_db_key[12:]
    return aesgcm.decrypt(nonce, ct, None)


def encrypt(message, key):
    backend = default_backend()
    algorithm = algorithms.AES(key)
    iv = os.urandom(12)  # GCM standard
    cipher = Cipher(algorithm, modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encryptor.tag + ct)


def decrypt(encrypted_message, key):
    backend = default_backend()
    encrypted_message_bytes = base64.urlsafe_b64decode(encrypted_message)
    iv, tag, ct = encrypted_message_bytes[:12], encrypted_message_bytes[12:28], encrypted_message_bytes[28:]
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, modes.GCM(iv, tag), backend=backend)
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode('utf-8')


def validate_password(entered_password: bytes, salt: bytes, stored_verifier: bytes) -> bool:
    key = derive_master_key(entered_password, salt)
    try:
        decrypted_data = decrypt(stored_verifier, key)
        return decrypted_data == b"known_plaintext"
    except (InvalidTag, ValueError):
        return False


def create_password_verifier(key: bytes) -> bytes:
    known_plaintext = b"known_plaintext"
    return encrypt(known_plaintext, key)


def encrypt_notes(notes: str, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, notes.encode(), None)


def decrypt_notes(encrypted_notes: bytes, key: bytes) -> str:
    aesgcm = AESGCM(key)
    nonce, ct = encrypted_notes[:12], encrypted_notes[12:]
    return aesgcm.decrypt(nonce, ct, None).decode()


class NotesVault(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon(resource_path("./icon.ico")))

        try:
            with open('key.enc', 'rb') as f:
                data = f.read()
            salt, encrypted_db_key = data[:16], data[16:]
        except FileNotFoundError:
            password, ok = self.prompt_password()
            if ok:
                salt = os.urandom(16)  # 128 bits
                master_key = derive_master_key(password, salt)
                db_encryption_key = generate_db_encryption_key()
                encrypted_db_key = encrypt_key(db_encryption_key, master_key)
                with open('key.enc', 'wb') as f:
                    f.write(salt + encrypted_db_key)
                self.master_key = master_key
                self.db_encryption_key = db_encryption_key
                self.initUI()
            else:
                self.close()
        else:
            password, ok = self.prompt_password()
            if ok:
                try:
                    self.master_key = derive_master_key(password, salt)
                    self.db_encryption_key = decrypt_key(encrypted_db_key, self.master_key)
                    self.initUI()
                except InvalidTag:
                    logging.exception("Decryption failed due to invalid tag, possibly wrong password")
                    QMessageBox.warning(self, "Error", "Failed to decrypt. Incorrect password entered.")
                    self.close()
                except Exception as e:
                    logging.exception("An unexpected error occurred")
                    QMessageBox.warning(self, "Error", f"An unexpected error occurred: {str(e)}")
                    self.close()
            else:
                self.close()

    def prompt_password(self):
        dialog = QInputDialog(self)
        dialog.inputMode = QInputDialog.InputMode.TextInput
        dialog.setLabelText(
            "Please enter a strong password to encrypt your notes securely.\n\nEnter your password:")
        dialog.setTextEchoMode(QLineEdit.EchoMode.Password)
        dialog.setFixedSize(500, 400)
        dialog.setWindowTitle('NotesVault')

        ok = dialog.exec()
        password = dialog.textValue().encode('utf-8')
        return password, ok

    def initUI(self):
        main_layout = QVBoxLayout()
        hbox = QHBoxLayout()
        main_layout.addLayout(hbox)
        icon_size = QSize(24, 24)
        button_font = QFont("Arial", 10)
        button_layout = QHBoxLayout()
        button_layout.addItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))

        self.save_button = QPushButton("Save")
        self.save_button.setFont(button_font)
        self.save_button.setIcon(QIcon(resource_path("save.png")))
        self.save_button.setIconSize(icon_size)
        self.save_button.clicked.connect(self.save_notes)
        button_layout.addWidget(self.save_button)

        self.load_button = QPushButton("Open")
        self.load_button.setFont(button_font)
        self.load_button.setIcon(QIcon(resource_path("open.png")))
        self.load_button.setIconSize(icon_size)
        self.load_button.clicked.connect(self.load_notes)
        button_layout.addWidget(self.load_button)

        self.markdown_button = QPushButton("Markdown")
        self.markdown_button.setFont(button_font)
        self.markdown_button.setIcon(QIcon(resource_path("single.png")))
        self.markdown_button.setIconSize(icon_size)
        self.markdown_button.clicked.connect(self.render_markdown)
        button_layout.addWidget(self.markdown_button)

        self.toggle_preview_button = QPushButton("Preview")
        self.toggle_preview_button.setFont(button_font)
        self.toggle_preview_button.setIcon(QIcon(resource_path("preview.png")))
        self.toggle_preview_button.setIconSize(icon_size)
        self.toggle_preview_button.clicked.connect(self.toggle_preview)
        button_layout.addWidget(self.toggle_preview_button)

        self.text_edit = QTextEdit()
        self.text_edit.setStyleSheet("border: none; border-radius: 4px;")
        hbox.addWidget(self.text_edit)

        self.text_display = QTextBrowser()
        self.text_display.setStyleSheet("border: none; border-radius: 4px;")
        hbox.addWidget(self.text_display)
        self.text_display.setVisible(False)

        button_layout.addItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))

        main_layout.addLayout(button_layout)

        self.setLayout(main_layout)
        self.setWindowTitle('NotesVault')
        self.resize(960, 640)
        self.show()

    def toggle_preview(self):
        self.text_display.setVisible(not self.text_display.isVisible())

    def render_markdown(self):
        current_text = self.text_edit.toPlainText()
        html_text = markdown(current_text)
        self.text_display.setHtml(html_text)

    def save_notes(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save Note", "", "Encrypted Notes Files (*.enc);;All Files (*)")
        if filename:
            if not filename.endswith('.enc'):
                filename += '.enc'
            note_text = self.text_edit.toPlainText()
            encrypted_note = encrypt_notes(note_text, self.db_encryption_key)
            with open(filename, "wb") as note_file:
                note_file.write(encrypted_note)

    def load_notes(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Open Note", "", "Encrypted Notes Files (*.enc);;All Files (*)")
        if filename:
            try:
                with open('key.enc', 'rb') as f:
                    encrypted_db_key = f.read()
                    salt, encrypted_db_key = encrypted_db_key[:16], encrypted_db_key[16:]  # Fixed line
                with open(filename, "rb") as note_file:
                    encrypted_note = note_file.read()
                self.db_encryption_key = decrypt_key(encrypted_db_key, self.master_key)
                decrypted_note = decrypt_notes(encrypted_note, self.db_encryption_key)
                self.text_edit.setPlainText(decrypted_note)
                self.render_markdown()
            except FileNotFoundError:
                logging.exception("File not found")
                QMessageBox.warning(self, "Error", "The specified file could not be found.")
            except InvalidTag:
                logging.exception("Decryption failed due to invalid tag")
                QMessageBox.warning(self, "Error", "Failed to decrypt. Incorrect password or corrupted data.")
            except ValueError:
                logging.exception("Value error occurred")
                QMessageBox.warning(self, "Error", "An error occurred while processing the file.")
            except Exception as e:
                logging.exception("An unexpected error occurred")
                QMessageBox.warning(self, "Error", f"An unexpected error occurred: {str(e)}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    qdarktheme.setup_theme("auto")
    ex = NotesVault()
    sys.exit(app.exec())
