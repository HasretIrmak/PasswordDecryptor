# PasswordDecryptor
# Password Cracker and Encryptor Tool

## Overview
This Python-based tool allows users to:
- Crack password hashes using a wordlist.
- Encrypt and decrypt wordlist files using AES encryption.

The tool provides an easy-to-use graphical user interface (GUI) built with `tkinter` for seamless password cracking and encryption processes.

## Features
- **Password Cracking:** Supports cracking MD5 and SHA-256 hashed passwords by comparing them to the entries in an encrypted wordlist.
- **File Encryption:** Encrypts wordlist files with a custom key using AES encryption.
- **Progress Bar:** Real-time progress display while attempting password cracking.
- **Key Generation:** Automatically generates a key for file encryption/decryption.

##Usage
Once the application is running, you can:

Encrypt a Wordlist: Use the "Encrypt Wordlist" button to select and encrypt a wordlist file.
Crack Password: Input a target password hash (MD5 or SHA-256), select the wordlist, and let the application attempt to find the matching password.
Generate Key: Click the "Generate Key" button to generate a new encryption key.
