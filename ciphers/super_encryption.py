"""
Super Encryption: Extended Vigenere Cipher + Columnar Transposition.
Combines substitution (Extended Vigenere 256) and transposition (Columnar).
Supports both raw binary data (bytes) and UTF-8 / ASCII text strings.
Uses irregular columnar transposition to ensure 100% exact byte preservation
without adding padding bytes.
"""

from typing import Union
from ciphers.vigenere_extended import ExtendedVigenereCipher


class SuperEncryption:
    """Implementation of Super Encryption (Extended Vigenere + Columnar Transposition)."""

    def __init__(self):
        self.vigenere = ExtendedVigenereCipher()

    @staticmethod
    def _get_column_order(key: str):
        if not key:
            raise ValueError("Transposition key cannot be empty.")
        # Returns column indices ordered by key character
        return [idx for idx, _ in sorted(enumerate(key), key=lambda x: (x[1], x[0]))]

    def columnar_encrypt(self, data: bytes, key: str) -> bytes:
        if not key:
            raise ValueError("Transposition key cannot be empty.")
        if not data:
            return b""

        num_cols = len(key)
        order = self._get_column_order(key)

        grid_cols = [bytearray() for _ in range(num_cols)]
        for i, byte in enumerate(data):
            grid_cols[i % num_cols].append(byte)

        result = bytearray()
        for col_idx in order:
            result.extend(grid_cols[col_idx])

        return bytes(result)

    def columnar_decrypt(self, data: bytes, key: str) -> bytes:
        if not key:
            raise ValueError("Transposition key cannot be empty.")
        if not data:
            return b""

        num_cols = len(key)
        order = self._get_column_order(key)
        total_len = len(data)

        num_rows = (total_len + num_cols - 1) // num_cols
        rem = total_len % num_cols

        col_lens = [
            num_rows if (c < rem or rem == 0) else (num_rows - 1)
            for c in range(num_cols)
        ]

        cols = [None] * num_cols
        offset = 0
        for col_idx in order:
            c_len = col_lens[col_idx]
            cols[col_idx] = data[offset : offset + c_len]
            offset += c_len

        restored = bytearray(total_len)
        for i in range(total_len):
            col_idx = i % num_cols
            row_idx = i // num_cols
            restored[i] = cols[col_idx][row_idx]

        return bytes(restored)

    def encrypt(
        self,
        data: Union[bytes, bytearray],
        vigenere_key: Union[str, bytes],
        transposition_key: str,
    ) -> bytes:
        if isinstance(vigenere_key, str):
            vigenere_key = vigenere_key.encode("utf-8")

        # Stage 1: Extended Vigenere Substitution
        sub_encrypted = self.vigenere.encrypt_bytes(bytes(data), vigenere_key)
        # Stage 2: Columnar Transposition
        super_encrypted = self.columnar_encrypt(sub_encrypted, transposition_key)
        return super_encrypted

    def decrypt(
        self,
        data: Union[bytes, bytearray],
        vigenere_key: Union[str, bytes],
        transposition_key: str,
    ) -> bytes:
        if isinstance(vigenere_key, str):
            vigenere_key = vigenere_key.encode("utf-8")

        # Stage 1: Inverse Columnar Transposition
        trans_decrypted = self.columnar_decrypt(bytes(data), transposition_key)
        # Stage 2: Inverse Extended Vigenere Substitution
        sub_decrypted = self.vigenere.decrypt_bytes(trans_decrypted, vigenere_key)
        return sub_decrypted

    def encrypt_text(self, text: str, vigenere_key: str, transposition_key: str) -> str:
        data_bytes = text.encode("utf-8")
        enc_bytes = self.encrypt(data_bytes, vigenere_key, transposition_key)
        return enc_bytes.decode("latin-1")

    def decrypt_text(self, ciphertext: str, vigenere_key: str, transposition_key: str) -> str:
        enc_bytes = ciphertext.encode("latin-1")
        dec_bytes = self.decrypt(enc_bytes, vigenere_key, transposition_key)
        try:
            return dec_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return dec_bytes.decode("latin-1")
