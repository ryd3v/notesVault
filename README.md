# Simple Encrypted Notes App

![License](https://img.shields.io/badge/license-MIT-blue.svg)

V2.0

![ALT](https://github.com/ryd3v/notesApp/blob/main/Screenshot_1.png)

![ALT](https://github.com/ryd3v/notesApp/blob/main/Screenshot_2.png)

## Overview

Encrypted notesApp is a desktop application built using PyQt5 and Python. It provides a secure and user-friendly
interface for creating, editing, and storing notes. The notes are encrypted using strong cryptography algorithms to
ensure the privacy of your data.

## Features

- Basic note-taking functionality
- Create, edit, and save encrypted notes
- AES-256 encryption for securing notes
- Password-protected access to the application
- Markdown support for rich text formatting
- Dark mode for better readability
- Cross-platform support (Windows, macOS, Linux)
- Resizable window

Enhanced security features include a randomly generated securely stored salt. Password-based encryption key derivation
using PBKDF2-HMAC-SHA256

## Password Validation

- Password should be at least 8 characters long
- Password should contain at least one uppercase letter
- Password should contain at least one lowercase letter
- Password should contain at least one numeric digit
- Password should contain at least one special character [!@#$%^&*()-_+=<>?/]
- Password is valid

----

## Installation

### Visit the [releases](https://github.com/ryd3v/notesApp/releases) page for the packed app

or

### Build From Source

### Requirements

- Python 3.x
- PyQt5

1. Clone the repository:
    ```bash
    git clone https://github.com/ryd3v/notesApp.git
    ```
2. Navigate to the project directory and install the required packages:
    ```bash
    pip install -r requirements.txt
    ```
3. Build the application using PyInstaller:
    ```bash
    pyinstaller notesApp.spec
    ```

## Usage

Run the `notesApp.exe` executable to launch the application.

----

## Q&A

### What is the salt file?

The concept of a "salt" in cryptography refers to random data that is used as an additional input along with the
user-provided password during the process of encryption or hashing. The salt ensures that even if two users have the
same password, their respective salts will differ, resulting in different encryption or hash outputs. This adds an extra
layer of security.

### How Does Salt Work in Encryption?

1. **Generation**: A salt is typically a random sequence of bytes generated once and stored for future use. It doesn't
   need to be kept secret; in fact, it's often stored alongside the encrypted data.

2. **Combination**: When a user provides a password for encryption or decryption, the salt is combined with this
   password. This can be done in a number of ways, but it usually involves appending or prepending the salt to the
   password.

3. **Key Derivation**: The salted password is then run through a key derivation function to produce an encryption key.
   This key is used for the actual encryption and decryption of data.

4. **Storage**: Since the salt is required to decrypt the data, it is usually stored alongside the encrypted data. When
   decryption is needed, the same salt is used in conjunction with the provided password to derive the encryption key
   again.

### Importance of Salt

1. **Uniqueness**: Because salts are unique, they ensure that identical passwords will produce different encryption
   keys, thus resulting in different ciphertexts.

2. **Resistance to Pre-computed Attacks**: Salts make it computationally infeasible for an attacker to use pre-computed
   tables (like rainbow tables) to reverse engineer the encryption key, because each salt would require its own set of
   tables.

3. **Brute-force Inefficiency**: An attacker cannot efficiently crack multiple encrypted items at once, because each
   item's encryption key is different due to the salt, even if the same password was used.

In our Encrypted Notes App, the salt is generated randomly and used along with the user-provided password to create a
secure encryption key. The salt itself is stored so that it can be used again for decryption or for generating the
encryption key for new data.

### How does the Key Derivation work?

In our Encrypted Notes App, the key derivation part is handled by the `derive_key` function, which is imported from
the `crypto` module. The function takes the user-provided password and a salt as its inputs and returns the derived
encryption key.

Here's how it generally works:

1. **User-Provided Password**: The password is collected from the user via a dialog box when the application starts.

2. **Salt**: The salt is either loaded from a saved file or generated randomly if it doesn't exist.

3. **Key Derivation**: The `derive_key` function is then called with the password and salt to produce an encryption key.

The encryption key is used for both encrypting and decrypting the notes.

The `derive_key` function typically uses a key derivation function (KDF) like PBKDF2, bcrypt, or scrypt to produce the
encryption key from the salt and the password.
