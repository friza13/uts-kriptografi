"""
Hill Cipher (26 Alphabet, Supports 2x2 and 3x3 Key Matrices).
Validates that det(K) mod 26 is coprime with 26.
Calculates inverse matrix mod 26 using adjugate matrix and modular inverse.
"""

import math
import re
from typing import List, Union


def _clean_alphabet(text: str) -> str:
    return re.sub(r"[^A-Za-z]", "", text).upper()


def mod_inverse(a: int, m: int = 26) -> int:
    a = a % m
    g = math.gcd(a, m)
    if g != 1:
        raise ValueError(f"Determinant ({a}) is not coprime with {m}. gcd({a}, {m}) = {g}")
    return pow(a, -1, m)


class HillCipher:
    """Implementation of Hill Cipher for 2x2 and 3x3 matrices."""

    def normalize_matrix(self, key: Union[List[List[int]], List[int], str]) -> List[List[int]]:
        """Parse key in 2D list, 1D list, or string format into a square 2x2 or 3x3 matrix."""
        if isinstance(key, str):
            clean_k = _clean_alphabet(key)
            if len(clean_k) == 4:
                n = 2
            elif len(clean_k) == 9:
                n = 3
            else:
                raise ValueError("String key length must be 4 (for 2x2) or 9 (for 3x3).")
            nums = [ord(c) - ord("A") for c in clean_k]
            return [nums[i * n : (i + 1) * n] for i in range(n)]

        if isinstance(key, list):
            if all(isinstance(row, list) for row in key):
                n = len(key)
                if n not in (2, 3) or any(len(row) != n for row in key):
                    raise ValueError("Key matrix must be 2x2 or 3x3.")
                return [[int(val) % 26 for val in row] for row in key]
            elif all(isinstance(val, (int, float)) for val in key):
                if len(key) == 4:
                    return [[int(key[0]), int(key[1])], [int(key[2]), int(key[3])]]
                elif len(key) == 9:
                    return [
                        [int(key[0]), int(key[1]), int(key[2])],
                        [int(key[3]), int(key[4]), int(key[5])],
                        [int(key[6]), int(key[7]), int(key[8])],
                    ]
                else:
                    raise ValueError("List key length must be 4 (for 2x2) or 9 (for 3x3).")

        raise ValueError("Invalid key format for Hill cipher.")

    def determinant(self, matrix: List[List[int]]) -> int:
        n = len(matrix)
        if n == 2:
            return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
        elif n == 3:
            return (
                matrix[0][0] * (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1])
                - matrix[0][1] * (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0])
                + matrix[0][2] * (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0])
            )
        raise ValueError("Only 2x2 and 3x3 matrices are supported.")

    def invert_matrix(self, matrix: List[List[int]]) -> List[List[int]]:
        n = len(matrix)
        det = self.determinant(matrix)
        det_mod = det % 26
        det_inv = mod_inverse(det_mod, 26)

        if n == 2:
            # Adjugate for 2x2: [[d, -b], [-c, a]]
            adj = [
                [matrix[1][1], -matrix[0][1]],
                [-matrix[1][0], matrix[0][0]],
            ]
            return [[(adj[r][c] * det_inv) % 26 for c in range(2)] for r in range(2)]

        elif n == 3:
            m = matrix
            c00 = (m[1][1] * m[2][2] - m[1][2] * m[2][1])
            c01 = -(m[1][0] * m[2][2] - m[1][2] * m[2][0])
            c02 = (m[1][0] * m[2][1] - m[1][1] * m[2][0])

            c10 = -(m[0][1] * m[2][2] - m[0][2] * m[2][1])
            c11 = (m[0][0] * m[2][2] - m[0][2] * m[2][0])
            c12 = -(m[0][0] * m[2][1] - m[0][1] * m[2][0])

            c20 = (m[0][1] * m[1][2] - m[0][2] * m[1][1])
            c21 = -(m[0][0] * m[1][2] - m[0][2] * m[1][0])
            c22 = (m[0][0] * m[1][1] - m[0][1] * m[1][0])

            # Transpose of cofactor matrix is adjugate
            adj = [
                [c00, c10, c20],
                [c01, c11, c21],
                [c02, c12, c22],
            ]
            return [[(adj[r][c] * det_inv) % 26 for c in range(3)] for r in range(3)]

        raise ValueError("Only 2x2 and 3x3 matrices are supported.")

    def encrypt(self, plaintext: str, key: Union[List[List[int]], List[int], str]) -> str:
        mat = self.normalize_matrix(key)
        det = self.determinant(mat) % 26
        # Will raise ValueError if not invertible mod 26
        mod_inverse(det, 26)

        n = len(mat)
        clean_p = _clean_alphabet(plaintext)
        if not clean_p:
            return ""

        # Pad with 'X' until length is a multiple of n
        rem = len(clean_p) % n
        if rem != 0:
            clean_p += "X" * (n - rem)

        result = []
        for i in range(0, len(clean_p), n):
            block = [ord(clean_p[i + j]) - ord("A") for j in range(n)]
            cipher_block = [0] * n
            for r in range(n):
                cipher_block[r] = sum(mat[r][c] * block[c] for c in range(n)) % 26
            for val in cipher_block:
                result.append(chr(val + ord("A")))

        return "".join(result)

    def decrypt(self, ciphertext: str, key: Union[List[List[int]], List[int], str]) -> str:
        mat = self.normalize_matrix(key)
        inv_mat = self.invert_matrix(mat)
        n = len(inv_mat)

        clean_c = _clean_alphabet(ciphertext)
        if not clean_c:
            return ""
        if len(clean_c) % n != 0:
            raise ValueError(f"Ciphertext length must be a multiple of {n} for Hill cipher.")

        result = []
        for i in range(0, len(clean_c), n):
            block = [ord(clean_c[i + j]) - ord("A") for j in range(n)]
            plain_block = [0] * n
            for r in range(n):
                plain_block[r] = sum(inv_mat[r][c] * block[c] for c in range(n)) % 26
            for val in plain_block:
                result.append(chr(val + ord("A")))

        return "".join(result)
