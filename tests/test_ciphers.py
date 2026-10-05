"""
Unit tests for UTS Kriptografi Cipher implementations.
Tests all 8 cipher algorithms and file encryption wrapper.
"""

import os
import unittest

from ciphers.vigenere_standard import StandardVigenereCipher
from ciphers.vigenere_autokey import AutokeyVigenereCipher
from ciphers.vigenere_extended import ExtendedVigenereCipher
from ciphers.playfair import PlayfairCipher
from ciphers.affine import AffineCipher
from ciphers.hill import HillCipher
from ciphers.super_encryption import SuperEncryption
from ciphers.enigma import EnigmaM3
from ciphers.file_crypto import FileCrypto


class TestVigenereStandard(unittest.TestCase):
    def setUp(self):
        self.cipher = StandardVigenereCipher()

    def test_known_vector(self):
        # Plaintext: ATTACKATDAWN, Key: LEMON -> Ciphertext: LXFOPVEFRNHR
        plaintext = "ATTACKATDAWN"
        key = "LEMON"
        ciphertext = self.cipher.encrypt(plaintext, key)
        self.assertEqual(ciphertext, "LXFOPVEFRNHR")
        decrypted = self.cipher.decrypt(ciphertext, key)
        self.assertEqual(decrypted, "ATTACKATDAWN")

    def test_non_alphabetic_characters_stripped(self):
        # Spaces, punctuation, and lowercase letters handled/stripped
        plaintext = "Attack at DAWN! 123"
        key = "lemon"
        ciphertext = self.cipher.encrypt(plaintext, key)
        self.assertEqual(ciphertext, "LXFOPVEFRNHR")
        decrypted = self.cipher.decrypt(ciphertext, key)
        self.assertEqual(decrypted, "ATTACKATDAWN")

    def test_reciprocal_random(self):
        plaintext = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        key = "SECRETKEY"
        encrypted = self.cipher.encrypt(plaintext, key)
        decrypted = self.cipher.decrypt(encrypted, key)
        self.assertEqual(decrypted, plaintext)

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            self.cipher.encrypt("HELLO", "")
        with self.assertRaises(ValueError):
            self.cipher.encrypt("HELLO", "123!@#")


class TestVigenereAutokey(unittest.TestCase):
    def setUp(self):
        self.cipher = AutokeyVigenereCipher()

    def test_known_vector(self):
        # Plaintext: ATTACKATDAWN, Key: LEMON
        # Keystream: LEMONATTACKA
        # Sum mod 26: LXFOPKTMDCGN
        plaintext = "ATTACKATDAWN"
        key = "LEMON"
        ciphertext = self.cipher.encrypt(plaintext, key)
        self.assertEqual(ciphertext, "LXFOPKTMDCGN")
        decrypted = self.cipher.decrypt(ciphertext, key)
        self.assertEqual(decrypted, "ATTACKATDAWN")

    def test_non_alphabetic_characters_stripped(self):
        plaintext = "Attack at Dawn! 123"
        key = "LEMON"
        ciphertext = self.cipher.encrypt(plaintext, key)
        self.assertEqual(ciphertext, "LXFOPKTMDCGN")
        decrypted = self.cipher.decrypt(ciphertext, key)
        self.assertEqual(decrypted, "ATTACKATDAWN")

    def test_reciprocal_long_text(self):
        plaintext = "KRIPTOGRAFIDENGANAUTOKEYVIGENERELEBIHAMANDARIPADASTANDAR"
        key = "KUNCI"
        ciphertext = self.cipher.encrypt(plaintext, key)
        decrypted = self.cipher.decrypt(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            self.cipher.encrypt("HELLO", "")
        with self.assertRaises(ValueError):
            self.cipher.encrypt("HELLO", "---")


class TestVigenereExtended(unittest.TestCase):
    def setUp(self):
        self.cipher = ExtendedVigenereCipher()

    def test_bytes_encryption_vector(self):
        data = bytes([10, 20, 30, 40, 50])
        key = bytes([5, 10])
        # Expected: [(10+5)%256, (20+10)%256, (30+5)%256, (40+10)%256, (50+5)%256] = [15, 30, 35, 50, 55]
        encrypted = self.cipher.encrypt_bytes(data, key)
        self.assertEqual(encrypted, bytes([15, 30, 35, 50, 55]))
        decrypted = self.cipher.decrypt_bytes(encrypted, key)
        self.assertEqual(decrypted, data)

    def test_binary_full_range(self):
        # All 256 byte values
        data = bytes(range(256))
        key = b"SECRET_KEY_123!@#"
        encrypted = self.cipher.encrypt_bytes(data, key)
        self.assertNotEqual(encrypted, data)
        decrypted = self.cipher.decrypt_bytes(encrypted, key)
        self.assertEqual(decrypted, data)

    def test_string_handling(self):
        text = "Hello World! Kriptografi 2026 @#$%"
        key = "MySecretKey"
        encrypted = self.cipher.encrypt(text, key)
        decrypted = self.cipher.decrypt(encrypted, key)
        self.assertEqual(decrypted, text)

    def test_invalid_key(self):
        with self.assertRaises(ValueError):
            self.cipher.encrypt_bytes(b"data", b"")


class TestPlayfair(unittest.TestCase):
    def setUp(self):
        self.cipher = PlayfairCipher()

    def test_matrix_generation(self):
        key = "MONARCHY"
        matrix = self.cipher.generate_matrix(key)
        # 5x5 matrix letters: M O N A R C H Y B D E F G I K L P Q S T U V W X Z
        flat_matrix = "".join(["".join(row) for row in matrix])
        expected = "MONARCHYBDEFGIKLPQSTUVWXZ"
        self.assertEqual(flat_matrix, expected)

    def test_known_vector_instrument(self):
        # Key: MONARCHY, Plaintext: INSTRUMENT -> pairs: IN ST RU ME NT
        # IN -> GA, ST -> TL, RU -> MZ, ME -> CL, NT -> RQ (or similar according to standard rules)
        key = "MONARCHY"
        plaintext = "INSTRUMENT"
        ciphertext = self.cipher.encrypt(plaintext, key)
        self.assertEqual(ciphertext, "GATLMZCLRQ")
        decrypted = self.cipher.decrypt(ciphertext, key)
        self.assertEqual(decrypted, "INSTRUMENT")

    def test_duplicate_characters_in_bigram(self):
        # "BALLOON" -> "BA LX LO ON"
        key = "MONARCHY"
        plaintext = "BALLOON"
        prepared = self.cipher.prepare_plaintext(plaintext)
        self.assertEqual(prepared, ["BA", "LX", "LO", "ON"])
        ciphertext = self.cipher.encrypt(plaintext, key)
        decrypted = self.cipher.decrypt(ciphertext, key)
        self.assertEqual(decrypted, "BALXLOON")

    def test_odd_length_padding(self):
        # "HELLO" -> "HE LX LO"
        key = "KEYWORD"
        prepared = self.cipher.prepare_plaintext("HELLO")
        self.assertEqual(prepared, ["HE", "LX", "LO"])

    def test_duplicate_x_uses_z_filler(self):
        # When duplicate letter is 'X', filler should be 'Z'
        prepared = self.cipher.prepare_plaintext("XX")
        self.assertEqual(prepared, ["XZ", "XZ"])

    def test_empty_plaintext(self):
        self.assertEqual(self.cipher.encrypt("", "KEY"), "")
        self.assertEqual(self.cipher.decrypt("", "KEY"), "")

    def test_reciprocal_property(self):
        key = "PLAYFAIR EXAMPLE"
        plaintext = "HIDETHEGOLDINTHEGREENTREE"
        ciphertext = self.cipher.encrypt(plaintext, key)
        decrypted = self.cipher.decrypt(ciphertext, key)
        # Decrypted contains padded X between EE -> "EX" "RE" "EX" etc.
        self.assertIn("HIDE", decrypted)
        self.assertIn("GOLD", decrypted)


class TestAffine(unittest.TestCase):
    def setUp(self):
        self.cipher = AffineCipher()

    def test_known_vector(self):
        # Formula: C = (a*P + b) % 26
        # Plaintext: AFFINECIPHER, a=5, b=8
        # A(0)*5+8 = 8 (I)
        # F(5)*5+8 = 33 % 26 = 7 (H)
        # F(5)*5+8 = 7 (H)
        # I(8)*5+8 = 48 % 26 = 22 (W)
        # N(13)*5+8 = 73 % 26 = 21 (V)
        # E(4)*5+8 = 28 % 26 = 2 (C)
        # C(2)*5+8 = 18 % 26 = 18 (S)
        # I(8)*5+8 = 22 (W)
        # P(15)*5+8 = 83 % 26 = 5 (F)
        # H(7)*5+8 = 43 % 26 = 17 (R)
        # E(4)*5+8 = 2 (C)
        # R(17)*5+8 = 93 % 26 = 15 (P)
        # Expected ciphertext: IHHWVCSWFRCP
        plaintext = "AFFINE CIPHER"
        a, b = 5, 8
        ciphertext = self.cipher.encrypt(plaintext, a, b)
        self.assertEqual(ciphertext, "IHHWVCSWFRCP")
        decrypted = self.cipher.decrypt(ciphertext, a, b)
        self.assertEqual(decrypted, "AFFINECIPHER")

    def test_coprime_validation(self):
        # gcd(a, 26) != 1 should raise ValueError
        with self.assertRaises(ValueError):
            self.cipher.encrypt("HELLO", 2, 3)
        with self.assertRaises(ValueError):
            self.cipher.encrypt("HELLO", 13, 5)
        with self.assertRaises(ValueError):
            self.cipher.encrypt("HELLO", 26, 1)

    def test_extended_gcd_mod_inverse(self):
        # 5 * 21 = 105 = 4*26 + 1 => 5^-1 mod 26 = 21
        self.assertEqual(self.cipher.mod_inverse(5, 26), 21)
        self.assertEqual(self.cipher.mod_inverse(7, 26), 15)
        self.assertEqual(self.cipher.mod_inverse(11, 26), 19)

    def test_reciprocal_all_valid_a(self):
        valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
        plaintext = "KRIPTOGRAFIAFFINECIPHERTESTING"
        for a in valid_a:
            for b in [0, 1, 7, 15, 25]:
                encrypted = self.cipher.encrypt(plaintext, a, b)
                decrypted = self.cipher.decrypt(encrypted, a, b)
                self.assertEqual(decrypted, plaintext)


class TestHill(unittest.TestCase):
    def setUp(self):
        self.cipher = HillCipher()

    def test_2x2_known_vector(self):
        # Matrix: [[3, 3], [2, 5]]
        # det = 15 - 6 = 9. gcd(9, 26) = 1.
        # Plaintext "HELP" -> H(7), E(4), L(11), P(15)
        # Block 1 [7, 4]: [3*7 + 3*4, 2*7 + 5*4] = [33%26, 34%26] = [7(H), 8(I)] -> "HI"
        # Block 2 [11, 15]: [3*11 + 3*15, 2*11 + 5*15] = [78%26, 97%26] = [0(A), 19(T)] -> "AT"
        # Expected: "HIAT"
        key_matrix = [[3, 3], [2, 5]]
        ciphertext = self.cipher.encrypt("HELP", key_matrix)
        self.assertEqual(ciphertext, "HIAT")
        decrypted = self.cipher.decrypt(ciphertext, key_matrix)
        self.assertEqual(decrypted, "HELP")

    def test_3x3_known_vector(self):
        # Key: [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
        # Plaintext: "ACT" -> A(0), C(2), T(19)
        # Expected: "POH"
        key_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
        ciphertext = self.cipher.encrypt("ACT", key_matrix)
        self.assertEqual(ciphertext, "POH")
        decrypted = self.cipher.decrypt(ciphertext, key_matrix)
        self.assertEqual(decrypted, "ACT")

    def test_string_key_format(self):
        # String key "DDCF" -> [[3, 3], [2, 5]] (D=3, D=3, C=2, F=5)
        ciphertext = self.cipher.encrypt("HELP", "DDCF")
        self.assertEqual(ciphertext, "HIAT")
        decrypted = self.cipher.decrypt(ciphertext, "DDCF")
        self.assertEqual(decrypted, "HELP")

    def test_odd_padding(self):
        # Plaintext length not multiple of n (e.g. length 3 for 2x2 matrix) -> pads with 'X'
        key_matrix = [[3, 3], [2, 5]]
        ciphertext = self.cipher.encrypt("HEL", key_matrix)
        self.assertEqual(len(ciphertext), 4)
        decrypted = self.cipher.decrypt(ciphertext, key_matrix)
        self.assertEqual(decrypted, "HELX")

    def test_invalid_determinant(self):
        # det divisible by 2 or 13 (gcd(det, 26) != 1)
        invalid_matrix = [[2, 4], [1, 2]]  # det = 0
        with self.assertRaises(ValueError):
            self.cipher.encrypt("HELP", invalid_matrix)

        invalid_matrix2 = [[2, 1], [4, 6]]  # det = 12 - 4 = 8 (gcd(8, 26)=2)
        with self.assertRaises(ValueError):
            self.cipher.encrypt("HELP", invalid_matrix2)


class TestSuperEncryption(unittest.TestCase):
    def setUp(self):
        self.cipher = SuperEncryption()

    def test_columnar_transposition_standalone(self):
        # Text transposition
        text = "HELLOWORLD"
        key = "3142"  # or keyword "DBEC"
        transposed = self.cipher.columnar_encrypt(text.encode("latin-1"), key)
        restored = self.cipher.columnar_decrypt(transposed, key)
        self.assertEqual(restored.decode("latin-1"), text)

    def test_super_encryption_bytes(self):
        data = b"Ini adalah data biner rahasia 1234567890 \x00\x01\xfe\xff"
        vigenere_key = b"VIGENEREPASS"
        transposition_key = "CRYPTO"
        encrypted = self.cipher.encrypt(data, vigenere_key, transposition_key)
        self.assertNotEqual(encrypted, data)
        self.assertEqual(len(encrypted), len(data))
        decrypted = self.cipher.decrypt(encrypted, vigenere_key, transposition_key)
        self.assertEqual(decrypted, data)

    def test_super_encryption_string(self):
        text = "Kriptografi Super Enkripsi Gabungan Extended Vigenere & Transposisi Kolom"
        vkey = "KUNCIUTAMA"
        tkey = "RAHASIA"
        encrypted = self.cipher.encrypt_text(text, vkey, tkey)
        decrypted = self.cipher.decrypt_text(encrypted, vkey, tkey)
        self.assertEqual(decrypted, text)


class TestEnigma(unittest.TestCase):
    def setUp(self):
        # Standard Enigma M3 setup: Rotors I, II, III, Reflector B, Plugboard empty
        self.enigma = EnigmaM3(
            rotors=["I", "II", "III"],
            reflector="B",
            ring_settings=[0, 0, 0],
            initial_positions=[0, 0, 0],
            plugboard=""
        )

    def test_reciprocal_property(self):
        # Enigma is inherently reciprocal: passing ciphertext back with same initial state recovers plaintext
        plaintext = "ENIGMAMACHINETESTINGMESSAGE"
        ciphertext = self.enigma.process_text(plaintext)
        self.assertNotEqual(ciphertext, plaintext)

        # Reset enigma to identical initial state
        decryptor = EnigmaM3(
            rotors=["I", "II", "III"],
            reflector="B",
            ring_settings=[0, 0, 0],
            initial_positions=[0, 0, 0],
            plugboard=""
        )
        decrypted = decryptor.process_text(ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_letter_never_encrypts_to_itself(self):
        # A fundamental property of Enigma (due to reflector)
        plaintext = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ciphertext = self.enigma.process_text(plaintext)
        for p, c in zip(plaintext, ciphertext):
            self.assertNotEqual(p, c)

    def test_plugboard_swapping(self):
        # Test with plugboard swapping 'A' <-> 'B', 'C' <-> 'D'
        plugboard_enigma = EnigmaM3(
            rotors=["I", "II", "III"],
            reflector="B",
            ring_settings=[0, 0, 0],
            initial_positions=[0, 0, 0],
            plugboard="AB CD"
        )
        plaintext = "SECRETWARCOMMUNICATION"
        ciphertext = plugboard_enigma.process_text(plaintext)

        reset_enigma = EnigmaM3(
            rotors=["I", "II", "III"],
            reflector="B",
            ring_settings=[0, 0, 0],
            initial_positions=[0, 0, 0],
            plugboard="AB CD"
        )
        decrypted = reset_enigma.process_text(ciphertext)
        self.assertEqual(decrypted, plaintext)


class TestFileCrypto(unittest.TestCase):
    def setUp(self):
        self.file_crypto = FileCrypto()

    def test_pack_and_unpack_packet(self):
        filename = "dokumen_rahasia.docx"
        data = b"PK\x03\x04Dummy docx payload content 1234567890"
        packet = self.file_crypto.pack(filename, data)
        self.assertTrue(packet.startswith(b"KRIPTO"))

        unpacked_name, unpacked_data = self.file_crypto.unpack(packet)
        self.assertEqual(unpacked_name, filename)
        self.assertEqual(unpacked_data, data)

    def test_file_encrypt_decrypt_vigenere(self):
        filename = "foto_profil.png"
        payload = os.urandom(1024)  # 1 KB binary data
        key = "KunciFileRahasia123"

        encrypted_packet = self.file_crypto.encrypt_file(
            filename=filename,
            data=payload,
            cipher_type="extended_vigenere",
            key=key
        )
        # Ensure ciphertext is not identical to payload
        self.assertNotEqual(encrypted_packet, payload)

        recovered_name, recovered_payload = self.file_crypto.decrypt_file(
            encrypted_data=encrypted_packet,
            cipher_type="extended_vigenere",
            key=key
        )
        self.assertEqual(recovered_name, filename)
        self.assertEqual(recovered_payload, payload)

    def test_file_encrypt_decrypt_super_encryption(self):
        filename = "laporan_keuangan.pdf"
        payload = b"%PDF-1.4 simulated pdf binary content \x00\xff\xfe\x01\x88\x99" * 20
        vkey = "PDF_SECRET_KEY"
        tkey = "COLUMN_PERM"

        encrypted_packet = self.file_crypto.encrypt_file(
            filename=filename,
            data=payload,
            cipher_type="super_encryption",
            key=vkey,
            transposition_key=tkey
        )
        recovered_name, recovered_payload = self.file_crypto.decrypt_file(
            encrypted_data=encrypted_packet,
            cipher_type="super_encryption",
            key=vkey,
            transposition_key=tkey
        )
        self.assertEqual(recovered_name, filename)
        self.assertEqual(recovered_payload, payload)

    def test_tampered_packet_raises_error(self):
        # Invalid packet without magic header raises ValueError
        with self.assertRaises(ValueError):
            self.file_crypto.unpack(b"INVALID_HEADER_DATA_12345")


if __name__ == "__main__":
    unittest.main()
