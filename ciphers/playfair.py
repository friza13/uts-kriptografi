"""
Playfair Cipher (5x5 Matrix, 25 Letters, I/J Combined).
Bigram substitution with duplicate character padding ('X' or 'Z'),
same row (shift right/left), same column (shift down/up), and rectangle rules.
"""

import re
from typing import List, Tuple, Dict


class PlayfairCipher:
    """Implementation of Playfair Cipher."""

    @staticmethod
    def _clean_text(text: str) -> str:
        text = re.sub(r"[^A-Za-z]", "", text).upper()
        return text.replace("J", "I")

    def generate_matrix(self, key: str) -> List[List[str]]:
        clean_key = self._clean_text(key)
        seen = set()
        letters = []

        for char in clean_key:
            if char not in seen:
                seen.add(char)
                letters.append(char)

        for char_code in range(ord("A"), ord("Z") + 1):
            char = chr(char_code)
            if char == "J":
                continue
            if char not in seen:
                seen.add(char)
                letters.append(char)

        matrix = [letters[i : i + 5] for i in range(0, 25, 5)]
        return matrix

    def _build_char_map(self, matrix: List[List[str]]) -> Dict[str, Tuple[int, int]]:
        char_map = {}
        for r in range(5):
            for c in range(5):
                char_map[matrix[r][c]] = (r, c)
        return char_map

    def prepare_plaintext(self, plaintext: str) -> List[str]:
        clean_p = self._clean_text(plaintext)
        if not clean_p:
            return []

        bigrams = []
        i = 0
        while i < len(clean_p):
            c1 = clean_p[i]
            if i + 1 < len(clean_p):
                c2 = clean_p[i + 1]
                if c1 == c2:
                    filler = "Z" if c1 == "X" else "X"
                    bigrams.append(c1 + filler)
                    i += 1
                else:
                    bigrams.append(c1 + c2)
                    i += 2
            else:
                filler = "Z" if c1 == "X" else "X"
                bigrams.append(c1 + filler)
                i += 1

        return bigrams

    def encrypt(self, plaintext: str, key: str) -> str:
        matrix = self.generate_matrix(key)
        pos = self._build_char_map(matrix)
        bigrams = self.prepare_plaintext(plaintext)

        cipher_bigrams = []
        for pair in bigrams:
            r1, c1 = pos[pair[0]]
            r2, c2 = pos[pair[1]]

            if r1 == r2:
                # Same row -> shift right
                c1_new = (c1 + 1) % 5
                c2_new = (c2 + 1) % 5
                cipher_bigrams.append(matrix[r1][c1_new] + matrix[r2][c2_new])
            elif c1 == c2:
                # Same column -> shift down
                r1_new = (r1 + 1) % 5
                r2_new = (r2 + 1) % 5
                cipher_bigrams.append(matrix[r1_new][c1] + matrix[r2_new][c2])
            else:
                # Rectangle -> swap columns
                cipher_bigrams.append(matrix[r1][c2] + matrix[r2][c1])

        return "".join(cipher_bigrams)

    def decrypt(self, ciphertext: str, key: str) -> str:
        clean_c = self._clean_text(ciphertext)
        if not clean_c:
            return ""
        if len(clean_c) % 2 != 0:
            raise ValueError("Ciphertext length must be even for Playfair cipher.")

        matrix = self.generate_matrix(key)
        pos = self._build_char_map(matrix)

        plain_bigrams = []
        for i in range(0, len(clean_c), 2):
            c1, c2 = clean_c[i], clean_c[i + 1]
            r1, col1 = pos[c1]
            r2, col2 = pos[c2]

            if r1 == r2:
                # Same row -> shift left
                col1_new = (col1 - 1) % 5
                col2_new = (col2 - 1) % 5
                plain_bigrams.append(matrix[r1][col1_new] + matrix[r2][col2_new])
            elif col1 == col2:
                # Same column -> shift up
                r1_new = (r1 - 1) % 5
                r2_new = (r2 - 1) % 5
                plain_bigrams.append(matrix[r1_new][col1] + matrix[r2_new][col2])
            else:
                # Rectangle -> swap columns
                plain_bigrams.append(matrix[r1][col2] + matrix[r2][col1])

        return "".join(plain_bigrams)
