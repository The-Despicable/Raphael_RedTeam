import os, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate_keypair() -> tuple[bytes, bytes]:
    sk = Ed25519PrivateKey.generate()
    return sk.public_key().public_bytes_raw(), sk.private_bytes_raw()


def encrypt(key: bytes, plaintext: bytes) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct).decode()


def decrypt(key: bytes, wire: str) -> bytes:
    raw = base64.b64decode(wire)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None)


# AES-CTR for sleep mask (no authentication tag, for performance)
def aes_ctr_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """Encrypt using AES-CTR (for sleep mask heap encryption).
    nonce must be exactly 16 bytes (the IV for CTR mode).
    """
    if len(nonce) != 16:
        raise ValueError("Nonce must be exactly 16 bytes for AES-CTR")
    cipher = Cipher(algorithms.AES(key[:32]), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_ctr_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt using AES-CTR (for sleep mask heap decryption).
    nonce must be exactly 16 bytes (the IV for CTR mode).
    """
    if len(nonce) != 16:
        raise ValueError("Nonce must be exactly 16 bytes for AES-CTR")
    cipher = Cipher(algorithms.AES(key[:32]), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()