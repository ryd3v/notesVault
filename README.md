# Simple Encrypted Notes App

![License](https://img.shields.io/badge/license-MIT-blue.svg)

V1.3.0

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
