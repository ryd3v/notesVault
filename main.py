import os
import sys

import cryptography
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QTextEdit, QPushButton, QInputDialog, QLineEdit

from crypto import encrypt, decrypt, derive_key, save_salt, load_salt


class NotesApp(QWidget):
    def __init__(self):
        super().__init__()

        existing_salt = load_salt()
        if existing_salt is None:
            existing_salt = os.urandom(16)
            save_salt(existing_salt)

        # Prompt user for password
        password, ok = QInputDialog.getText(self, 'Password', 'Enter your password:', QLineEdit.Password)

        if ok:
            self.key = derive_key(password.encode(), existing_salt)
            self.initUI()
        else:
            self.close()

    def initUI(self):
        layout = QVBoxLayout()

        self.text_area = QTextEdit()
        layout.addWidget(self.text_area)

        self.save_button = QPushButton("Save Note")
        self.save_button.clicked.connect(self.save_notes)
        layout.addWidget(self.save_button)

        self.load_button = QPushButton("Load Note")
        self.load_button.clicked.connect(self.load_notes)
        layout.addWidget(self.load_button)

        self.setLayout(layout)
        self.setWindowTitle('Encrypted Notes')
        self.show()

    def save_notes(self):
        note_text = self.text_area.toPlainText()
        encrypted_note = encrypt(note_text, self.key)
        with open("note.enc", "wb") as note_file:
            note_file.write(encrypted_note)

    def load_notes(self):
        try:
            with open("note.enc", "rb") as note_file:
                encrypted_note = note_file.read()
            decrypted_note = decrypt(encrypted_note, self.key)
            self.text_area.setPlainText(decrypted_note)
        except FileNotFoundError:
            self.text_area.setPlainText("No saved notes found.")
        except cryptography.fernet.InvalidToken:
            self.text_area.setPlainText("Failed to decrypt. Incorrect key or corrupted data.")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = NotesApp()
    sys.exit(app.exec_())
