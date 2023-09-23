![ALT](https://github.com/ryd3v/notesVault/blob/main/notesVault-logo-main-01.png)

 ----
 
 # notesVault Encrypted Notes App

#### Ryan Collins 2023

![License](https://img.shields.io/badge/license-MIT-blue.svg)

V2.0.6

![ALT](https://github.com/ryd3v/notesApp/blob/main/Screenshot_1.png)

![ALT](https://github.com/ryd3v/notesApp/blob/main/Screenshot_2.png)

## Overview

Encrypted notesApp is a desktop application built using PyQt5 and Python. It provides a secure and user-friendly
interface for creating, editing, and storing notes. The notes are encrypted using strong cryptography algorithms to
ensure the privacy of your data.

## Features

- Basic note-taking functionality
- Create, edit, and save encrypted notes
- Argon2 Encryption 
- AES-256-GCM Encryption for saved notes
- Password-protected access to the application
- Markdown support for rich text formatting
- Markdown preview and toggle button 
- Dark mode for better readability
- Cross-platform support (Windows, macOS, Linux)
- Resizable window

Enhanced security features include a randomly generated securely stored salt. Password-based encryption key derivation
using Argon2 for Key Derivation.

## Password Validation

- Password should be at least 8 characters long
- Password should contain at least one uppercase letter
- Password should contain at least one lowercase letter
- Password should contain at least one numeric digit
- Password should contain at least one special character [!@#$%^&*()-_+=<>?/]
- Password is valid

#### A 16-character password is recommended!

----

## How our app works:

### 1. Importing Libraries
Firstly, we import the necessary libraries like `cryptography` and our custom `crypto` module to handle cryptographic operations.

### 2. Salt Generation and Storage
When the app is initialized, a salt is either generated randomly or loaded from a file(salt.dat). This salt is crucial for the key derivation process. It's a random sequence of bytes that is used in combination with your password to generate a unique key.

### 3. User Password and Validation
The password is obtained from you via a dialog box. This password is then validated to meet certain criteria like length and complexity, as noted above.

### 4. Key Derivation
Your password and the generated/loaded salt are then used to derive a unique encryption key using Argon2 in the `crypto` module.

### 5. Text Encryption and Decryption
When you save a note, the text is encrypted using the derived key before being saved to a file.

### 6. Key Functions and Algorithms

#### Argon2 (Current Version)
We are using Argon2, a more modern and secure key derivation function. Argon2 is resistant to GPU cracking attacks and offers better security features. Argon2id, a hybrid of Argon2i and Argon2d, which provides both side-channel attack resistance and brute-force attack resistance.

### 7. Data Storage
Finally, the encrypted note is stored in a `.enc` file. The salt is also stored, as it is required for decryption.

---

## Installation

### Visit the [releases](https://github.com/ryd3v/notesApp/releases) page for the packed app

or

### Build From Source

### Requirements

- Python 3.x
- PyQt5

1. Clone the repository:
    ```bash
    git clone https://github.com/ryd3v/notesVault
    ```
2. Navigate to the project directory and install the required packages:
    ```bash
    pip install -r requirements.txt
    ```
3. Build the application using PyInstaller:
    ```bash
    pyinstaller notesVault.spec
    ```

### Archlinux 

On Archlinux you will need to install Qt 5.x

```bash
  sudo pacman -S qt5-base
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

## Argon2 Encryption Algorithm

### What is Argon2?

Argon2 is a key derivation function that was selected as the winner of the Password Hashing Competition in 2015. It's
designed to be secure against a range of attacks, including side-channel attacks and timing attacks. Argon2 is highly
customizable, which allows developers to configure the time, memory, and parallelism factors to balance between security
and performance.

### Why Use Argon2?

- **Security**: Argon2 is resistant to a wide array of attacks, including timing attacks and side-channel attacks.
- **Customizable**: Parameters for time, memory, and parallelism can be adjusted based on the security requirements
  and hardware capabilities.
- **Widely Accepted**: Being the winner of the Password Hashing Competition, it is recognized and recommended by
  security experts.

### How We Use Argon2 in Encrypted Notes App

In our application, we use Argon2id, a hybrid version combining Argon2i and Argon2d, to derive the encryption keys from
the user's password. We have tuned Argon2 to use a minimum configuration of 2 GiB of memory, an iteration count of 2,
and 8 degree of parallelism, balancing both security and performance.

By utilizing Argon2, we ensure that your notes are encrypted in a secure and efficient manner.

## AES-256-GCM Encryption

### Overview

The Advanced Encryption Standard (AES) is a symmetric encryption algorithm that was established by the U.S. National Institute of Standards and Technology (NIST) in 2001. AES-256-GCM (Galois/Counter Mode) is a high-performance, secure variant of AES that uses a 256-bit key for encryption and includes an authentication tag for message integrity.

### Key Features

#### Symmetric Encryption
- AES-256-GCM is a symmetric encryption algorithm, meaning the same key is used for both encryption and decryption. The key size is 256 bits, making it one of the most secure encryption standards available.

#### Authenticated Encryption
- GCM (Galois/Counter Mode) is an authenticated encryption mode that not only provides confidentiality but also provides integrity and authenticity assurances on the encrypted data.

#### High Performance
- AES-256-GCM is optimized for high performance, making it suitable for encrypting large amounts of data or high-speed data streams.

#### Nonce
- AES-256-GCM requires a nonce (Number Once) to provide security. The nonce must never be reused with the same key.

### How It Works in Our App

1. **Key Derivation**: The encryption key is derived using Argon2, a secure key derivation function, along with a salt. This key is 256 bits long, conforming to the AES-256-GCM standard.

2. **Initialization Vector (IV)**: A unique IV (also known as a nonce in the context of GCM) is generated each time a note is encrypted. This ensures that the same plaintext encrypted with the same key will produce different ciphertexts based on the different IVs.

3. **Encryption**: The plaintext note is encrypted using AES-256-GCM, and an authentication tag is generated.

4. **Data Storage**: The IV, authentication tag, and encrypted note are concatenated and stored securely.

5. **Decryption**: When reading an encrypted note, the IV and authentication tag are extracted, and the note is decrypted using the same key. The authentication tag is verified to ensure the integrity of the data.

----

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the
warranties of merchantability, fitness for a particular purpose and non-infringement. In no event shall the authors or
copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort or
otherwise, arising from, out of or in connection with the software or the use or other dealings in the software.

The user assumes all responsibility for the secure and proper use of this software, including but not limited to the
protection of their own data. The creators of this software are not responsible for any data loss, unauthorized access,
or any other damage or loss that may occur due to the use or misuse of this software.
