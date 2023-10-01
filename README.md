# NotesVault

![ALT](https://github.com/ryd3v/notesVault/blob/main/Screenshot-1.png)
![ALT](https://github.com/ryd3v/notesVault/blob/main/Screenshot-2.png)

## Overview

NotesVault is a secure notes application that allows you to create, save, and load encrypted notes. The application
leverages advanced cryptographic algorithms to ensure the privacy and security of your notes.

NotesVault uses PBKDFF2 in the process of deriving encryption keys from your chosen password. The utilization of 650,000
iterations in the PBKDF2 (Password-Based Key Derivation Function 2) mechanism significantly increases the computational
effort required to derive the encryption keys, thereby providing a robust defense against brute-force and dictionary
attacks. This key derivation process ensures that even if an attacker gains access to the encrypted files (note.enc or
key.enc), they won't be able to easily derive the encryption keys without the **correct password**.

Furthermore, separating the master key and the database encryption key, and keeping them securely encrypted, adds an
additional layer of security. The key.enc file holds the encrypted database key, which is encrypted using the master key
derived from the user's password. This approach provides a solid security foundation, ensuring that the encryption keys
remain secure and that the encrypted data (notes) remains confidential and protected against unauthorized access.

These measures, along with the absence of a direct hash of the password, contribute to the overall security of the
NotesVault application.

## Master Key Creation:

1. **Password Input**: When the user first launches NotesVault, they are prompted to enter a password. This password is
   crucial as it forms the basis for creating the master key.
2. **Key Derivation**:
    - The application uses the Password-Based Key Derivation Function 2 (PBKDF2) to generate a master key from the
      user's password.
    - A random salt is generated (or read from the `key.enc` file if it exists) to ensure uniqueness of the master key
      even if the same password is used across different instances.
    - The PBKDF2 function, configured with 650,000 iterations and SHA-256 as the hash function, processes the user's
      password along with the salt to derive a 32-byte (256-bit) master key. This iterative process ensures that
      brute-force or dictionary attacks are computationally expensive.

***Note**, a 5 word, digit separator password is suggested, example: ``Dreamless64Malt68Wad52Expel03Twenty1``

## Notes Encryption and Decryption:

1. **Database Encryption Key Generation**:
    - A separate database encryption key is generated using the `os.urandom` function, which produces a random 32-byte (
      256-bit) key.
    - This database encryption key is then encrypted using the master key with AES-GCM (Galois/Counter Mode), and stored
      in the `key.enc` file along with the salt.

2. **Notes Encryption**:
    - When the user saves notes, the application uses the AES-GCM encryption algorithm to encrypt the notes.
    - A new random nonce (Number Used Once) is generated for each encryption process to ensure encryption uniqueness
      even with the same data and key.
    - The database encryption key (decrypted using the master key) is used to encrypt the notes. The resultant encrypted
      data, along with the nonce, is stored in the `note.enc` file.

3. **Notes Decryption**:
    - When the user wants to access their notes, the application reads the encrypted database key from the `key.enc`
      file, decrypts it using the master key, and then uses the decrypted database encryption key to decrypt the notes
      from the `note.enc` file.
    - The decryption process reverses the encryption steps to recover the original plaintext notes, which are then
      displayed in the application for the user to view and edit.

This structure creates a secure environment where the master key derived from the user's password serves as a secure
method to further protect the database encryption key, which in turn is used to encrypt and decrypt the user's notes.
When a user decrypts and displays a note for editing, the data on disk remains in its encrypted form.

---- 

## Can a hash be derived from the key.enc or note file?

1. **One-Way Nature of Hash Functions**:
    - Hash functions are designed to be one-way, meaning given a hash value, it is computationally infeasible to
      determine the original input value.
    - The `key.enc` file contains an encrypted version of the database encryption key, and not a hash of the user's
      password. Similarly, the `notes.enc` file contains encrypted notes, not a hash.

2. **Salt Usage**:
    - The usage of a unique salt when deriving the master key ensures that even if two users have the same password, the
      derived master keys will be different. This salt is stored in the `key.enc` file.
    - The salt prevents pre-computed dictionary attacks (rainbow tables) from being effective, as each password has a
      unique hash due to the unique salt.

3. **Key Derivation Process**:
    - The PBKDF2 function used for key derivation is designed to be slow and computationally intensive, particularly
      with a high iteration count (650,000 in our case). This deliberate design is to deter brute-force and dictionary
      attacks by making them way too time-consuming to be practical.

4. **Encryption of Database Encryption Key**:
    - The database encryption key is encrypted using the master key and stored in the `key.enc` file. Without the
      correct master key (derived from the correct password), the encrypted database encryption key remains secure and
      indistinguishable from random data.

5. **AES-GCM Encryption**:
    - The Advanced Encryption Standard in Galois/Counter Mode (AES-GCM) used for encrypting the database encryption key
      and the notes provides confidentiality and authenticity assurance. It does not provide an easily reversible hash
      of the password, and the encrypted data does not reveal information about the key or the plaintext.

6. **Lack of Password Verification Data**:
    - There isn't a stored hash of the password in the `key.enc` or `notes.enc` files that could be used for hash-based
      password cracking attempts. The files contain encrypted data that requires the correct key for decryption, and
      there isn't a mechanism to verify a password guess without going through the full key derivation and decryption
      process.

7. **No Direct Relationship**:
    - There is no direct relationship between the encrypted data in the `key.enc` and `notes.enc` files and the user's
      password that would allow for a hash to be derived without the **original password**.

Due to these factors, an attacker cannot derive a hash of the user's password from the `key.enc` and `notes.enc` files,
making password cracking impractical.

----

## Note Editing and Saving Procedure:

When a user opens a note in NotesVault, the following actions occur:

1. **Decryption**:
    - The selected note is decrypted using the derived database encryption key.
    - The decrypted content is displayed in the text editor within the application for the user to view and/or edit.

2. **In-Memory Editing**:
    - Any modifications made by the user to the note's content occur in-memory within the application.
    - At this stage, the encrypted file on the disk remains unchanged.

3. **Preview and Markdown Rendering**:
    - Users can preview the note with Markdown rendering within the application.
    - This preview does not affect the encrypted note saved on the disk.

4. **Saving Changes**:
    - To save any modifications, the user must explicitly save the note again using the "Save" button.
    - Upon clicking "Save", the user is prompted to either overwrite the existing note file or save as a new note file.
    - If the user chooses to overwrite the existing note, the original encrypted note file on the disk is replaced with
      a new encrypted file that contains the updated note content.
    - If the user chooses to save as a new note, a new encrypted note file is created on the disk, and the original
      encrypted note file remains unchanged.

5. **Encryption of Modified Note**:
    - When saving, the updated note content is encrypted using the derived database encryption key before being written
      to disk.
    - The encryption ensures that the updated note content is securely stored on the disk, protecting the user's data.

This procedure ensures that the user's note data remains securely encrypted at rest on the disk, while still providing a
user-friendly interface for viewing, editing, and saving notes. The explicit save action required from the user helps
prevent accidental loss of data and ensures that the user has control over when and how their data is saved and
encrypted.

----

### Importance of the `key.enc` File:

Losing the `key.enc` file or having it deleted is a critical event as it holds the encrypted database key
which is crucial for decrypting the notes.

The `key.enc` file is pivotal to the security infrastructure of NotesVault. It contains the encrypted database
encryption key which is required to decrypt and access the contents of your notes. The database encryption key is
encrypted using a master key derived from your password and a salt value, and this encrypted form is what's stored in
the `key.enc` file.

#### What happens if the `key.enc` file is lost or deleted?

1. **Loss of Access**:
    - Without the `key.enc` file, you will lose the ability to decrypt your notes. The application will not be able to
      derive the necessary database encryption key to decrypt the note contents, rendering your notes inaccessible.

2. **Irreversible Damage**:
    - The loss of the `key.enc` file is irreversible. Without it, the encrypted notes are just random data - there's no
      way to retrieve the original content.

3. **No Recovery**:
    - There isn't a recovery mechanism for a lost or deleted `key.enc` file. It's crucial that you keep this file in a
      safe and secure location to continue accessing your notes.

4. **No Backdoor**:
    - NotesVault is designed with a strong security model. There's no backdoor or alternative method to decrypt the
      notes without the `key.enc` file and your password. This design ensures the privacy and security of your data but
      also means loss of the `key.enc` file results in permanent loss of access to your notes.

### Recommendations:

- **Backup**: It's highly recommended to keep a secure backup of the `key.enc` file in a trusted location. This backup
  will be your only recourse in case the original `key.enc` file is lost or deleted.
- **Secure Storage**: Store the `key.enc` file in a secure, reliable, and protected storage medium to prevent accidental
  deletion or unauthorized access. For example [Proton Drive](https://proton.me/drive)

By understanding the importance of the `key.enc` file and following the recommended precautions, you can ensure the
long-term safety and accessibility of your notes.

--- 

## Database?

The term "database encryption key" in the context of our application refers to a symmetric key that is used to encrypt
and decrypt the contents of individual note files. A naming convention rather than referring to a traditional database.
The term "database" implies a collection of notes, where each file represents a "record" within this conceptual
database.

Here's a breakdown of the process:

1. **Master Key Derivation**:
    - When the application starts, a master key is derived from a user-supplied password using the `derive_master_key`
      function, which utilizes the PBKDF2 key derivation algorithm with a salt.

2. **Database Encryption Key Generation (or Note Encryption Key)**:
    - If the `key.enc` file doesn't exist (which means the application is run for the first time or the file is lost), a
      new "database encryption key" is generated using the `generate_db_encryption_key` function, which generates a
      random 256-bit key.

3. **Database Encryption Key Storage**:
    - The "database encryption key" is then encrypted using the master key with the `encrypt_key` function, which
      employs AES-GCM for encryption. This encrypted "database encryption key" along with the salt is stored in
      the `key.enc` file.

4. **Note Encryption**:
    - When a note is saved, the `encrypt_notes` function is called, which encrypts the note content using the "database
      encryption key" (now decrypted from the `key.enc` file using the master key) with AES-GCM.

5. **Note Decryption**:
    - When a note is loaded, the `decrypt_notes` function is called, which decrypts the note content using the "database
      encryption key" with AES-GCM.

So, in this setup, the "database encryption key" is acting as the symmetric key for encrypting and decrypting individual
notes, and it's encrypted and stored in the `key.enc` file for security reasons. The term "database" is a bit of a
misnomer if one is expecting a traditional database setup. It's more of a conceptual or logical database where each note
file represents a "record" and the file system acts as the "database."

## Features

- **Create Notes**: Easily create new notes with a simple and intuitive interface.
- **Save and Load**: Save your notes to disk in an encrypted format and load them back when needed.
- **Markdown Support**: Render your notes in Markdown format for better readability.
- **Strong Encryption**: Utilizes AES-256-GCM for note encryption and PBKDF2 for password-based key derivation.

## Algorithms Used

### AES-256-GCM

- **What**: Advanced Encryption Standard with a 256-bit key size, used in Galois/Counter Mode (GCM).
- **Why**: Provides both encryption and integrity verification.
- **How**: Encrypts the notes using a key derived from the user's password.

### PBKDF2 (Password-Based Key Derivation Function 2)

- **What**: A cryptographic key derivation function.
- **Why**: Derives a cryptographic key from the user's password to ensure secure encryption and decryption.
- **How**: Uses the user's password along with a salt value to derive a key for encrypting and decrypting notes.

## Usage

1. **Start the App**: Run the application executable.
2. **Enter Password**: On startup, the application will prompt you to enter a strong password which will be used for
   encryption.
3. **Create or Load Notes**: Use the interface to create new notes or load existing ones.
4. **Save Notes**: Use the "Save" button to save notes to disk in an encrypted format.

## Dependencies

- PyQt6: For the graphical user interface.
- cryptography: For AES-256-GCM encryption and PBKDF2 key derivation.
- Markdown: For rendering Markdown text.

## How to Install

1. Clone the repository or download the source code.
2. Install the required packages using `pip install -r requirements.txt`.
3. Run the application.

## Contributing

Contributions are welcome! Please read the contributing guidelines before submitting any changes.

## License

This project is licensed under the MIT License.

## Disclaimer

The software is provided "as is", without any guarantee of any kind, express or implied. This includes, but is not
limited to, the warranties of merchantability, fitness for a particular purpose, and noninfringement. The authors or
copyright holders bear no liability for any claims, damages, or other liabilities that may arise, whether in an action
of contract, tort, or otherwise, from, in connection with, or in relation to the software, its use, or other dealings
with the software.
