import base64
import logging
import os
import sys

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon, QAction, QPalette, QColor
from PyQt6.QtWidgets import QMenuBar, QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton, \
    QInputDialog, \
    QLineEdit, QTextBrowser, QFileDialog, QSizePolicy, QSpacerItem, QMessageBox, QDialog, QLabel
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


def generate_key(password: str, salt: bytes = None) -> (bytes, bytes):
    if salt is None:
        salt = os.urandom(16)  # 128 bits

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=650000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8')), salt


def encrypt(message, key):
    iv = os.urandom(12)  # GCM standard
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encryptor.tag + ct)


def decrypt(encrypted_message, key):
    encrypted_message_bytes = base64.urlsafe_b64decode(encrypted_message)
    iv, tag, ct = encrypted_message_bytes[:12], encrypted_message_bytes[12:28], encrypted_message_bytes[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode('utf-8')


def create_password_verifier(key: bytes) -> bytes:
    return encrypt("known_plaintext", key)


def validate_password(entered_password: bytes, salt: bytes, stored_verifier: bytes) -> bool:
    key, _ = generate_key(entered_password.decode('utf-8'), salt)
    try:
        return decrypt(stored_verifier, key) == "known_plaintext"
    except (InvalidTag, ValueError):
        return False


def encrypt_notes(notes: str, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, notes.encode('utf-8'), None)


def decrypt_notes(encrypted_notes: bytes, key: bytes) -> str:
    aesgcm = AESGCM(key)
    nonce, ct = encrypted_notes[:12], encrypted_notes[12:]
    return aesgcm.decrypt(nonce, ct, None).decode('utf-8')


class NotesVault(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon(resource_path("./icon.ico")))
        self.init_ui()

        try:
            with open('key.enc', 'rb') as f:
                data = f.read()
            salt, encrypted_db_key = data[:16], data[16:]
            self.db_encryption_key, _ = generate_key(self.prompt_password(), salt)
            self.initUI()
        except FileNotFoundError:
            password = self.prompt_password()
            salt = os.urandom(16)  # 128 bits
            self.db_encryption_key, salt = generate_key(password, salt)
            with open('key.enc', 'wb') as f:
                f.write(salt + self.db_encryption_key)
            self.initUI()
        except (InvalidTag, ValueError):
            logging.exception("Decryption failed due to invalid tag, possibly wrong password")
            QMessageBox.warning(self, "Error", "Failed to decrypt. Incorrect password entered.")
            self.close()
        except Exception as e:
            logging.exception("An unexpected error occurred")
            QMessageBox.warning(self, "Error", f"An unexpected error occurred: {str(e)}")
            self.close()

    def prompt_password(self):
        dialog = QInputDialog(self)
        dialog.inputMode = QInputDialog.InputMode.TextInput
        dialog.setLabelText("Enter a password to encrypt your notes securely.\n\nEnter your password:")
        dialog.setTextEchoMode(QLineEdit.EchoMode.Password)
        dialog.setFixedSize(500, 400)
        dialog.setWindowTitle('Notes Vault - A Secure Notes Application')
        dialog.setStyleSheet(self.get_stylesheet())
        if dialog.exec():
            return dialog.textValue()
        else:
            self.close()

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        QApplication.instance().setPalette(self.get_palette())

    def init_ui(self):
        self.dark_mode = True
        self.default_palette = QApplication.instance().palette()

    def get_palette(self):
        palette = QPalette()

        if self.dark_mode:
            palette.setColor(QPalette.ColorRole.Window, QColor(30, 31, 34))
            palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.Base, QColor(15, 15, 15))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(30, 31, 34))
            palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.Button, QColor(30, 31, 34))
            palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
            palette.setColor(QPalette.ColorRole.Highlight, QColor(59, 130, 246).lighter())
            palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
            self.text_edit.setStyleSheet("QTextEdit { background-color: #1e1f22; color: #ffffff; }")
            self.text_display.setStyleSheet("QTextBrowser { background-color: #1e1f22; color: #ffffff; }")
            self.theme_action.setText("Switch to Light Mode ☀️")
        else:
            palette.setColor(QPalette.ColorRole.Window, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.black)
            palette.setColor(QPalette.ColorRole.Base, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.AlternateBase, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.black)
            palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.black)
            palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.black)
            palette.setColor(QPalette.ColorRole.Button, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.black)
            palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
            palette.setColor(QPalette.ColorRole.Highlight, QColor(59, 130, 246).darker())
            palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.white)
            self.text_edit.setStyleSheet("QTextEdit { background-color: #ffffff; color: #000000; }")
            self.text_display.setStyleSheet("QTextBrowser { background-color: #ffffff; color: #000000; }")
            self.theme_action.setText("Switch to Dark Mode 🌙")

        return palette

    def get_stylesheet(self):
        return """
            QLabel {
                font-size: 12pt;
            }
            QLineEdit {
                font-size: 12pt;
            }
        """

    def initUI(self):
        main_layout = QVBoxLayout()

        menu_bar = QMenuBar(self)
        main_layout.setMenuBar(menu_bar)

        file_menu = menu_bar.addMenu('File')
        file_menu.addAction(QAction('Save', self, triggered=self.save_notes))
        file_menu.addAction(QAction('Open', self, triggered=self.load_notes))
        file_menu.addAction(QAction('Markdown', self, triggered=self.render_markdown))
        file_menu.addAction(QAction('Preview', self, triggered=self.toggle_preview))
        file_menu.addAction(QAction('Close', self, triggered=self.close))

        settings_menu = menu_bar.addMenu('Settings')
        self.theme_action = QAction('Switch Theme', self, triggered=self.toggle_theme)
        settings_menu.addAction(self.theme_action)

        about_menu = menu_bar.addMenu('About')
        about_menu.addAction(QAction('About Notes Vault', self, triggered=self.show_about_dialog))

        hbox = QHBoxLayout()
        main_layout.addLayout(hbox)

        text_edit_layout = QVBoxLayout()
        text_display_layout = QVBoxLayout()

        self.text_edit = QTextEdit()
        self.text_edit.setStyleSheet("border: none; border-radius: 6px;")
        text_edit_layout.addWidget(self.text_edit)

        self.text_display = QTextBrowser()
        self.text_display.setStyleSheet("border: none; border-radius: 6px;")
        text_display_layout.addWidget(self.text_display)
        self.text_display.setVisible(False)

        hbox.addLayout(text_edit_layout)
        hbox.addLayout(text_display_layout)

        button_layout = QHBoxLayout()
        button_layout.addItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))

        self.save_button = QPushButton("Save")
        self.save_button.clicked.connect(self.save_notes)
        button_layout.addWidget(self.save_button)

        self.load_button = QPushButton("Open")
        self.load_button.clicked.connect(self.load_notes)
        button_layout.addWidget(self.load_button)

        self.markdown_button = QPushButton("Markdown")
        self.markdown_button.clicked.connect(self.render_markdown)
        button_layout.addWidget(self.markdown_button)

        self.toggle_preview_button = QPushButton("Preview")
        self.toggle_preview_button.clicked.connect(self.toggle_preview)
        button_layout.addWidget(self.toggle_preview_button)

        button_layout.addItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum))

        main_layout.addLayout(button_layout)

        self.setLayout(main_layout)
        self.setWindowTitle('Notes Vault')
        self.resize(960, 640)
        self.show()

    def show_about_dialog(self):
        about_dialog = QDialog(self)
        about_dialog.setWindowTitle('Notes Vault')
        about_layout = QVBoxLayout(about_dialog)
        about_label = QLabel(
            "Notes Vault v4.1.1\n"
            "Author: Ryan Collins\n"
            "Email: hello@ryd3v.com\n"
            "Website: https://ryd3v.com\n"
            "Source: https://github.com/ryd3v/notesVault\n"
            "Copyright © Ryan Collins"
        )
        about_layout.addWidget(about_label)

        spacer = QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        about_layout.addItem(spacer)

        disclaimer_label = QLabel(
            "Disclaimer: Use this application at your own risk.\n"
            "The author is not responsible for any loss of data or other issues.\n"
            "A Five(5) word, digit(0-9) separated password is suggested.\n"
            "The software is provided \"as is\", without any guarantee of any kind, express or implied.\n"
            "This includes, but is not limited to, the warranties of merchantability, fitness for a particular\n"
            "purpose, and noninfringement. The authors or copyright holders bear no liability for any claims,\n"
            "damages, or other liabilities that may arise, whether in an action of contract, tort, or otherwise,\n"
            "from, in connection with, or in relation to the software, its use, or other dealings with the software."
        )
        about_layout.addWidget(disclaimer_label)

        about_dialog.setStyleSheet(self.get_stylesheet())
        about_dialog.exec()

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
                with open(filename, "rb") as note_file:
                    encrypted_note = note_file.read()
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
    app.setStyle("Fusion")
    ex = NotesVault()
    sys.exit(app.exec())
