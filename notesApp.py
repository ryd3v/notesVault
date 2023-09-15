import os
import sys

import cryptography
from PyQt5.QtCore import QSize
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton, QInputDialog, \
    QLineEdit, QTextBrowser, QFileDialog, QSizePolicy, QSpacerItem
from PyQt5.QtGui import QPalette, QColor, QFont, QIcon, QFontDatabase
from markdown import markdown

from crypto import encrypt, decrypt, derive_key, save_salt, load_salt


def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


class NotesApp(QWidget):
    def __init__(self):
        super().__init__()

        # Load existing salt or create a new one
        existing_salt = load_salt()
        if existing_salt is None:
            existing_salt = os.urandom(16)
            save_salt(existing_salt)

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
        main_layout = QVBoxLayout()
        hbox = QHBoxLayout()
        main_layout.addLayout(hbox)
        icon_size = QSize(24, 24)
        button_font = QFont("Arial", 10)
        button_layout = QHBoxLayout()
        button_layout.addItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))

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

        self.markdown_button = QPushButton("Preview")
        self.markdown_button.setFont(button_font)
        self.markdown_button.setIcon(QIcon(resource_path("preview.png")))
        self.markdown_button.setIconSize(icon_size)
        self.markdown_button.clicked.connect(self.render_markdown)
        button_layout.addWidget(self.markdown_button)

        self.toggle_preview_button = QPushButton("Markdown")
        self.toggle_preview_button.setFont(button_font)
        self.toggle_preview_button.setIcon(QIcon(resource_path("single.png")))
        self.toggle_preview_button.clicked.connect(self.toggle_preview)
        button_layout.addWidget(self.toggle_preview_button)

        self.text_edit = QTextEdit()
        hbox.addWidget(self.text_edit)

        self.text_display = QTextBrowser()
        hbox.addWidget(self.text_display)
        button_layout.addItem(QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum))

        main_layout.addLayout(button_layout)

        self.setLayout(main_layout)
        self.setWindowTitle('Encrypted Notes App')
        self.resize(960, 540)
        self.show()

    def toggle_preview(self):
        self.text_display.setVisible(not self.text_display.isVisible())

    def render_markdown(self):
        current_text = self.text_edit.toPlainText()
        html_text = markdown(current_text)
        self.text_display.setHtml(html_text)

    def save_notes(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        filename, _ = QFileDialog.getSaveFileName(self, "Save Note", "", "Encrypted Notes Files (*.enc);;All Files (*)",
                                                  options=options)

        if filename:
            if not filename.endswith('.enc'):
                filename += '.enc'
            note_text = self.text_edit.toPlainText()
            encrypted_note = encrypt(note_text, self.key)
            with open(filename, "wb") as note_file:
                note_file.write(encrypted_note)

    def load_notes(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        filename, _ = QFileDialog.getOpenFileName(self, "Open Note", "", "Encrypted Notes Files (*.enc);;All Files (*)",
                                                  options=options)

        if filename:
            try:
                with open(filename, "rb") as note_file:
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

    app.setStyle("Fusion")

    font_id = QFontDatabase.addApplicationFont("./fonts/Roboto-Regular.ttf")
    font_families = QFontDatabase.applicationFontFamilies(font_id)
    if len(font_families) != 0:
        font = QFont(font_families[0])
        font.setPointSize(12)
        app.setFont(font)

    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
    palette.setColor(QPalette.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipBase, QColor(0, 0, 0))
    palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
    palette.setColor(QPalette.Text, QColor(255, 255, 255))
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
    palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
    palette.setColor(QPalette.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
    app.setPalette(palette)

    ex = NotesApp()
    sys.exit(app.exec_())
