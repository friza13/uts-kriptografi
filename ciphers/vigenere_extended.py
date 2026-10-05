"""
Extended Vigenere Cipher (256 ASCII / Full Byte-by-Byte).
Operates over the full 256-byte space (0-255).
C[i] = (P[i] + K[i % len(K)]) % 256
P[i] = (C[i] - K[i % len(K)]) % 256
Supports both raw binary bytes and text strings.
"""

from typing import Union


class ExtendedVigenereCipher:
    """Implementation of 256-character / 256-byte Extended Vigenere Cipher."""

    def encrypt_bytes(self, data: Union[bytes, bytearray], key: Union[bytes, bytearray]) -> bytes:
        if not key:
            raise ValueError("Key cannot be empty.")
        if not data:
            return b""

        k_len = len(key)
        encrypted = bytearray(len(data))
        for i, b in enumerate(data):
            encrypted[i] = (b + key[i % k_len]) % 256
        return bytes(encrypted)

    def decrypt_bytes(self, data: Union[bytes, bytearray], key: Union[bytes, bytearray]) -> bytes:
        if not key:
            raise ValueError("Key cannot be empty.")
        if not data:
            return b""

        k_len = len(key)
        decrypted = bytearray(len(data))
        for i, b in enumerate(data):
            decrypted[i] = (b - key[i % k_len]) % 256
        return bytes(decrypted)

    def encrypt(self, text: Union[str, bytes], key: Union[str, bytes]) -> Union[str, bytes]:
        if isinstance(text, (bytes, bytearray)):
            key_bytes = key if isinstance(key, (bytes, bytearray)) else key.encode("utf-8")
            return self.encrypt_bytes(text, key_bytes)

        if not text:
            return ""

        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        data_bytes = text.encode("utf-8")
        enc_bytes = self.encrypt_bytes(data_bytes, key_bytes)
        return enc_bytes.decode("latin-1")

    def decrypt(self, text: Union[str, bytes], key: Union[str, bytes]) -> Union[str, bytes]:
        if isinstance(text, (bytes, bytearray)):
            key_bytes = key if isinstance(key, (bytes, bytearray)) else key.encode("utf-8")
            return self.decrypt_bytes(text, key_bytes)

        if not text:
            return ""

        key_bytes = key.encode("utf-8") if isinstance(key, str) else key
        enc_bytes = text.encode("latin-1")
        dec_bytes = self.decrypt_bytes(enc_bytes, key_bytes)
        try:
            return dec_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return dec_bytes.decode("latin-1")
