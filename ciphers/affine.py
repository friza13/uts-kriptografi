"""
Affine Cipher (26 Uppercase Alphabet).
Formula:
  Encryption: C = (a * P + b) mod 26
  Decryption: P = a^-1 * (C - b) mod 26
Requires gcd(a, 26) == 1.
Computes modular inverse using Extended Euclidean Algorithm.
"""

import math
import re


def _clean_alphabet(text: str) -> str:
    return re.sub(r"[^A-Za-z]", "", text).upper()


def extended_gcd(a: int, b: int):
    """Extended Euclidean Algorithm returning (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


class AffineCipher:
    """Implementation of Affine Cipher."""

    @staticmethod
    def mod_inverse(a: int, m: int = 26) -> int:
        a = a % m
        g, x, _ = extended_gcd(a, m)
        if g != 1:
            raise ValueError(f"Key 'a' ({a}) is not coprime with {m}. gcd({a}, {m}) = {g}")
        return (x % m + m) % m

    def encrypt(self, plaintext: str, a: int, b: int) -> str:
        if math.gcd(a, 26) != 1:
            raise ValueError(f"Key 'a' ({a}) must be coprime with 26. gcd({a}, 26) = {math.gcd(a, 26)}")

        clean_p = _clean_alphabet(plaintext)
        result = []
        for char in clean_p:
            p_val = ord(char) - ord("A")
            c_val = (a * p_val + b) % 26
            result.append(chr(c_val + ord("A")))

        return "".join(result)

    def decrypt(self, ciphertext: str, a: int, b: int) -> str:
        if math.gcd(a, 26) != 1:
            raise ValueError(f"Key 'a' ({a}) must be coprime with 26. gcd({a}, 26) = {math.gcd(a, 26)}")

        a_inv = self.mod_inverse(a, 26)
        clean_c = _clean_alphabet(ciphertext)
        result = []
        for char in clean_c:
            c_val = ord(char) - ord("A")
            p_val = (a_inv * (c_val - b)) % 26
            result.append(chr(p_val + ord("A")))

        return "".join(result)
