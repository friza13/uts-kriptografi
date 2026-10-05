"""
Standard Vigenere Cipher (26 Uppercase Alphabet).
Non-alphabet characters are stripped from plaintext.
Ciphertext contains only uppercase A-Z characters without spaces.
"""

import re


def _clean_alphabet(text: str) -> str:
    """Keep only ASCII alphabet letters and convert to uppercase."""
    return re.sub(r"[^A-Za-z]", "", text).upper()


class StandardVigenereCipher:
    """Implementation of 26-character Standard Vigenere Cipher."""

    @staticmethod
    def clean_text(text: str) -> str:
        return _clean_alphabet(text)

    def encrypt(self, plaintext: str, key: str) -> str:
        clean_p = _clean_alphabet(plaintext)
        clean_k = _clean_alphabet(key)

        if not clean_k:
            raise ValueError("Key must contain at least one alphabetic character.")

        k_len = len(clean_k)
        result = []
        for i, char in enumerate(clean_p):
            p_val = ord(char) - ord("A")
            k_val = ord(clean_k[i % k_len]) - ord("A")
            c_val = (p_val + k_val) % 26
            result.append(chr(c_val + ord("A")))

        return "".join(result)

    def decrypt(self, ciphertext: str, key: str) -> str:
        clean_c = _clean_alphabet(ciphertext)
        clean_k = _clean_alphabet(key)

        if not clean_k:
            raise ValueError("Key must contain at least one alphabetic character.")

        k_len = len(clean_k)
        result = []
        for i, char in enumerate(clean_c):
            c_val = ord(char) - ord("A")
            k_val = ord(clean_k[i % k_len]) - ord("A")
            p_val = (c_val - k_val) % 26
            result.append(chr(p_val + ord("A")))

        return "".join(result)
