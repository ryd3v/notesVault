import os
import sys

import cryptography
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton, QInputDialog, \
    QLineEdit, \
    QTextBrowser
from markdown import markdown

from crypto import encrypt, decrypt, derive_key, save_salt, load_salt


class NotesApp(QWidget):
    def __init__(self):
        super().__init__()

        # Load existing salt or create a new one
        existing_salt = load_salt()
        if existing_salt is None:
            existing_salt = os.urandom(16)
            save_salt(existing_salt)

        # Prompt user for password
        dialog = QInputDialog(self)
        dialog.setInputMode(QInputDialog.TextInput)
        dialog.setLabelText('Enter your password:')
        dialog.setTextEchoMode(QLineEdit.Password)
        dialog.setFixedSize(400, 300)
        dialog.setWindowTitle('Encrypted Notes App')
        ok = dialog.exec_()
        password = dialog.textValue()

        if ok:
            self.key = derive_key(password.encode(), existing_salt)
            self.initUI()
        else:
            self.close()

    def initUI(self):
        layout = QVBoxLayout()
        hbox = QHBoxLayout()

        # QTextEdit for editing notes
        self.text_edit = QTextEdit()
        hbox.addWidget(self.text_edit)

        # QTextBrowser for displaying Markdown
        self.text_display = QTextBrowser()
        hbox.addWidget(self.text_display)
        layout.addLayout(hbox)

        self.save_button = QPushButton("Save Note")
        self.save_button.clicked.connect(self.save_notes)
        layout.addWidget(self.save_button)

        self.load_button = QPushButton("Load Note")
        self.load_button.clicked.connect(self.load_notes)
        layout.addWidget(self.load_button)

        self.markdown_button = QPushButton("Render Markdown")
        self.markdown_button.clicked.connect(self.render_markdown)
        layout.addWidget(self.markdown_button)

        self.setLayout(layout)
        self.setWindowTitle('Encrypted Notes App')
        self.resize(1024, 768)
        self.show()

    def render_markdown(self):
        current_text = self.text_edit.toPlainText()
        html_text = markdown(current_text)
        self.text_display.setHtml(html_text)

    def save_notes(self):
        note_text = self.text_edit.toPlainText()
        encrypted_note = encrypt(note_text, self.key)
        with open("note.enc", "wb") as note_file:
            note_file.write(encrypted_note)

    def load_notes(self):
        try:
            with open("note.enc", "rb") as note_file:
                encrypted_note = note_file.read()
            decrypted_note = decrypt(encrypted_note, self.key)
            self.text_edit.setPlainText(decrypted_note)
            self.render_markdown()  # Automatically render Markdown when a note is loaded
        except FileNotFoundError:
            self.text_edit.setPlainText("No saved notes found.")
        except cryptography.fernet.InvalidToken:
            self.text_edit.setPlainText("Failed to decrypt. Incorrect key or corrupted data.")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = NotesApp()
    sys.exit(app.exec_())
