import hashlib
from cryptography.fernet import Fernet

# Hash calculation
def hash_password(password, algorithm='md5'):
    """
    Hash a password using the specified algorithm (default: md5).
    """
    if algorithm == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    else:
        raise ValueError("Unsupported hash algorithm!")

# Password cracker
def password_cracker(wordlist, target_hash, algorithm):
    """
    Attempt to find the password by comparing hashes from a wordlist.
    """
    for word in wordlist:
        hashed_word = hash_password(word, algorithm)
        if hashed_word == target_hash:
            return word
    return None

# Key generation
def generate_key(file_name="key.key"):
    """
    Generate and save an encryption key.
    """
    key = Fernet.generate_key()
    with open(file_name, 'wb') as key_file:
        key_file.write(key)
    return key

# Key loading
def load_key(file_name="key.key"):
    """
    Load an existing encryption key.
    """
    with open(file_name, 'rb') as key_file:
        return key_file.read()

# Encrypt wordlist
def encrypt_wordlist(input_file, output_file, key):
    """
    Encrypt the contents of a wordlist file.
    """
    fernet = Fernet(key)
    with open(input_file, 'rb') as file:
        data = file.read()
    encrypted = fernet.encrypt(data)
    with open(output_file, 'wb') as file:
        file.write(encrypted)

# Decrypt wordlist
def decrypt_wordlist(input_file, key):
    """
    Decrypt the contents of an encrypted wordlist file.
    """
    fernet = Fernet(key)
    with open(input_file, 'rb') as file:
        encrypted_data = file.read()
    return fernet.decrypt(encrypted_data).decode().splitlines()
