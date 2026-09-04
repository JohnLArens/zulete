import os
from cryptography.fernet import Fernet

def _fernet():
    key = os.environ.get("ZULETE_MASTER_KEY","").encode()
    if not key:
        raise RuntimeError("ZULETE_MASTER_KEY is not configured.")
    return Fernet(key)

def encrypt_text(value: str) -> str:
    if not value:
        return ""
    return _fernet().encrypt(value.encode()).decode()

def decrypt_text(value: str) -> str:
    if not value:
        return ""
    return _fernet().decrypt(value.encode()).decode()
