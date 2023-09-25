# -----------------------------------------------------------------------------
# Copyright (C) 2023 Ryan Collins
#
# Author: Ryan Collins
# Email: hello@ryd3v
# Social: @ryd3v
# Version: 3.1.0
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
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# -----------------------------------------------------------------------------

import base64
import os
import sys
import bcrypt

from PyQt6.QtCore import QSize
from PyQt6.QtGui import QPalette, QColor, QFont, QIcon, QFontDatabase
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton, QInputDialog, \
    QLineEdit, QTextBrowser, QFileDialog, QSizePolicy, QSpacerItem, QMessageBox
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from markdown import markdown
import qdarktheme


def derive_key(password, salt):
    bcrypt_hash = bcrypt.hashpw(password, salt)
    return bcrypt_hash[:32]


def save_salt(salt, filename='key.dat'):
    with open(filename, 'wb') as f:
        f.write(salt)


def load_salt(filename='key.dat'):
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        return None


def save_hash(bcrypt_hash, filename='hash.dat'):
    with open(filename, 'wb') as f:
        f.write(bcrypt_hash)


# New function to load bcrypt hash
def load_hash(filename='hash.dat'):
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        return None


def encrypt(message, key):
    backend = default_backend()
    algorithm = algorithms.AES(key)
    iv = os.urandom(12)  # GCM standard
    cipher = Cipher(algorithm, modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encryptor.tag + ct)


def decrypt(encrypted_message, key):
    backend = default_backend()
    encrypted_message_bytes = base64.urlsafe_b64decode(encrypted_message)
    iv, tag, ct = encrypted_message_bytes[:12], encrypted_message_bytes[12:28], encrypted_message_bytes[28:]
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, modes.GCM(iv, tag), backend=backend)
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode('utf-8')


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(char.islower() for char in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one numeric digit."
    special_characters = "!@#$%^&*()-_+=<>?/"
    if not any(char in special_characters for char in password):
        return False, "Password must contain at least one special character."
    return True, "Password is valid."


class NotesVault(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon(resource_path("./icon.ico")))
        existing_salt = load_salt()
        if existing_salt is None:
            existing_salt = bcrypt.gensalt()
            save_salt(existing_salt)
        dialog = QInputDialog(self)
        dialog.inputMode = QInputDialog.InputMode.TextInput
        dialog.setLabelText(
            "Please enter a strong password to encrypt your notes securely using AES-256-GCM.\n\nEnter your password:")
        dialog.setTextEchoMode(QLineEdit.EchoMode.Password)
        dialog.setFixedSize(500, 400)
        dialog.setWindowTitle('NoteVault')
        ok = dialog.exec()
        password = dialog.textValue().encode('utf-8')
        if ok:
            saved_hash = load_hash()  # Load the saved hash
            if saved_hash is None or bcrypt.checkpw(password, saved_hash):
                if saved_hash is None:
                    new_hash = bcrypt.hashpw(password, existing_salt)
                    save_hash(new_hash)
                self.key = derive_key(password, existing_salt)
                self.initUI()
            else:
                QMessageBox.warning(self, "Invalid Password", "Incorrect password.")
                self.close()
        else:
            self.close()

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
        self.markdown_button.setIcon(QIcon(resource_path("preview.png")))
        self.markdown_button.setIconSize(icon_size)
        self.markdown_button.clicked.connect(self.render_markdown)
        button_layout.addWidget(self.markdown_button)

        self.toggle_preview_button = QPushButton("Preview")
        self.toggle_preview_button.setFont(button_font)
        self.toggle_preview_button.setIcon(QIcon(resource_path("single.png")))
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
            encrypted_note = encrypt(note_text, self.key)
            with open(filename, "wb") as note_file:
                note_file.write(encrypted_note)

    def load_notes(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Open Note", "", "Encrypted Notes Files (*.enc);;All Files (*)")

        if filename:
            try:
                with open(filename, "rb") as note_file:
                    encrypted_note = note_file.read()
                decrypted_note = decrypt(encrypted_note, self.key)
                self.text_edit.setPlainText(decrypted_note)
                self.render_markdown()
            except FileNotFoundError:
                self.text_edit.setPlainText("No saved notes found.")
            except InvalidTag:
                self.text_edit.setPlainText("Failed to decrypt. Incorrect key or corrupted data.")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    qdarktheme.setup_theme("auto")
    ex = NotesVault()
    sys.exit(app.exec())
