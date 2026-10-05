"""
Integration tests for Flask Web Application & REST API (Phase 2).
Tests UI rendering, text encryption/decryption API for all 8 ciphers,
and binary file encryption/decryption with metadata header restoration.
"""

import io
import json
import unittest

from app import app


class TestAppIntegration(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_index_route(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn("Friza Tri Maulana", html)
        self.assertIn("237006125", html)
        self.assertIn("Kriptografi", html)

    # 1. Standard Vigenere
    def test_api_vigenere_standard(self):
        payload = {
            "cipher": "vigenere_standard",
            "plaintext": "Attack at dawn!",
            "key": "LEMON",
        }
        res = self.client.post("/api/encrypt/text", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["ciphertext"], "LXFOPVEFRNHR")
        self.assertTrue("base64" in data)
        self.assertTrue("hex" in data)

        # Decrypt
        dec_payload = {
            "cipher": "vigenere_standard",
            "ciphertext": data["ciphertext"],
            "key": "LEMON",
        }
        res_dec = self.client.post("/api/decrypt/text", json=dec_payload)
        self.assertEqual(res_dec.status_code, 200)
        dec_data = res_dec.get_json()
        self.assertEqual(dec_data["decrypted"], "ATTACKATDAWN")

    # 2. Auto-Key Vigenere
    def test_api_vigenere_autokey(self):
        payload = {
            "cipher": "vigenere_autokey",
            "plaintext": "Attack at dawn!",
            "key": "LEMON",
        }
        res = self.client.post("/api/encrypt/text", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["ciphertext"], "LXFOPKTMDCGN")

        dec_payload = {
            "cipher": "vigenere_autokey",
            "ciphertext": data["ciphertext"],
            "key": "LEMON",
        }
        res_dec = self.client.post("/api/decrypt/text", json=dec_payload)
        self.assertEqual(res_dec.status_code, 200)
        dec_data = res_dec.get_json()
        self.assertEqual(dec_data["decrypted"], "ATTACKATDAWN")

    # 3. Extended Vigenere
    def test_api_vigenere_extended(self):
        payload = {
            "cipher": "vigenere_extended",
            "plaintext": "Hello Kripto 2026! #$%",
            "key": "MySecretPass",
        }
        res = self.client.post("/api/encrypt/text", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")

        dec_payload = {
            "cipher": "vigenere_extended",
            "ciphertext": data["ciphertext"],
            "key": "MySecretPass",
        }
        res_dec = self.client.post("/api/decrypt/text", json=dec_payload)
        self.assertEqual(res_dec.status_code, 200)
        dec_data = res_dec.get_json()
        self.assertEqual(dec_data["decrypted"], "Hello Kripto 2026! #$%")

    # 4. Playfair
    def test_api_playfair(self):
        payload = {
            "cipher": "playfair",
            "plaintext": "INSTRUMENT",
            "key": "MONARCHY",
        }
        res = self.client.post("/api/encrypt/text", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["ciphertext"], "GATLMZCLRQ")
        self.assertTrue("matrix" in data)
        self.assertEqual(len(data["matrix"]), 5)

        dec_payload = {
            "cipher": "playfair",
            "ciphertext": data["ciphertext"],
            "key": "MONARCHY",
        }
        res_dec = self.client.post("/api/decrypt/text", json=dec_payload)
        self.assertEqual(res_dec.status_code, 200)
        dec_data = res_dec.get_json()
        self.assertEqual(dec_data["decrypted"], "INSTRUMENT")

    # 5. Affine
    def test_api_affine(self):
        payload = {
            "cipher": "affine",
            "plaintext": "AFFINE CIPHER",
            "a": 5,
            "b": 8,
        }
        res = self.client.post("/api/encrypt/text", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["ciphertext"], "IHHWVCSWFRCP")

        dec_payload = {
            "cipher": "affine",
            "ciphertext": data["ciphertext"],
            "a": 5,
            "b": 8,
        }
        res_dec = self.client.post("/api/decrypt/text", json=dec_payload)
        self.assertEqual(res_dec.status_code, 200)
        dec_data = res_dec.get_json()
        self.assertEqual(dec_data["decrypted"], "AFFINECIPHER")

    # 6. Hill
    def test_api_hill_2x2(self):
        payload = {
            "cipher": "hill",
            "plaintext": "HELP",
            "matrix": [[3, 3], [2, 5]],
        }
        res = self.client.post("/api/encrypt/text", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["ciphertext"], "HIAT")
        self.assertTrue("inv_matrix" in data)
        self.assertTrue("det" in data)

        dec_payload = {
            "cipher": "hill",
            "ciphertext": data["ciphertext"],
            "matrix": [[3, 3], [2, 5]],
        }
        res_dec = self.client.post("/api/decrypt/text", json=dec_payload)
        self.assertEqual(res_dec.status_code, 200)
        dec_data = res_dec.get_json()
        self.assertEqual(dec_data["decrypted"], "HELP")

    # 7. Super Encryption
    def test_api_super_encryption(self):
        payload = {
            "cipher": "super_encryption",
            "plaintext": "SuperSecretKripto2026",
            "key": "KEYVIGENERE",
            "transposition_key": "COLUMNKEY",
        }
        res = self.client.post("/api/encrypt/text", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")

        dec_payload = {
            "cipher": "super_encryption",
            "ciphertext": data["ciphertext"],
            "key": "KEYVIGENERE",
            "transposition_key": "COLUMNKEY",
        }
        res_dec = self.client.post("/api/decrypt/text", json=dec_payload)
        self.assertEqual(res_dec.status_code, 200)
        dec_data = res_dec.get_json()
        self.assertEqual(dec_data["decrypted"], "SuperSecretKripto2026")

    # 8. Enigma
    def test_api_enigma(self):
        payload = {
            "cipher": "enigma",
            "plaintext": "ENIGMAMACHINETEST",
            "rotors": ["I", "II", "III"],
            "initial_positions": [0, 0, 0],
            "reflector": "B",
            "plugboard": "AB CD",
        }
        res = self.client.post("/api/encrypt/text", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertNotEqual(data["ciphertext"], "ENIGMAMACHINETEST")

        # Decrypt with identical initial settings
        dec_payload = {
            "cipher": "enigma",
            "ciphertext": data["ciphertext"],
            "rotors": ["I", "II", "III"],
            "initial_positions": [0, 0, 0],
            "reflector": "B",
            "plugboard": "AB CD",
        }
        res_dec = self.client.post("/api/decrypt/text", json=dec_payload)
        self.assertEqual(res_dec.status_code, 200)
        dec_data = res_dec.get_json()
        self.assertEqual(dec_data["decrypted"], "ENIGMAMACHINETEST")

    # Decrypt from Base64 or Hex
    def test_api_decrypt_formats(self):
        payload = {
            "cipher": "vigenere_standard",
            "plaintext": "HELLOWORLD",
            "key": "KEY",
        }
        res = self.client.post("/api/encrypt/text", json=payload)
        data = res.get_json()

        # Decrypt using Base64 format
        dec_b64 = self.client.post(
            "/api/decrypt/text",
            json={
                "cipher": "vigenere_standard",
                "ciphertext": data["base64"],
                "input_format": "base64",
                "key": "KEY",
            },
        )
        self.assertEqual(dec_b64.get_json()["decrypted"], "HELLOWORLD")

        # Decrypt using Hex format
        dec_hex = self.client.post(
            "/api/decrypt/text",
            json={
                "cipher": "vigenere_standard",
                "ciphertext": data["hex"],
                "input_format": "hex",
                "key": "KEY",
            },
        )
        self.assertEqual(dec_hex.get_json()["decrypted"], "HELLOWORLD")

    # File Encryption & Decryption
    def test_api_file_crypto_workflow(self):
        filename = "tugas_laporan.pdf"
        file_bytes = b"%PDF-1.4 Simulated PDF binary data with bytes \x00\x01\xfe\xff" * 50
        key = "SuperSecretFileKey123"

        # Encrypt File
        enc_res = self.client.post(
            "/api/encrypt/file",
            data={
                "file": (io.BytesIO(file_bytes), filename),
                "cipher": "extended_vigenere",
                "key": key,
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(enc_res.status_code, 200)
        encrypted_bytes = enc_res.data
        self.assertNotEqual(encrypted_bytes, file_bytes)

        # Decrypt File
        dec_res = self.client.post(
            "/api/decrypt/file",
            data={
                "file": (io.BytesIO(encrypted_bytes), "encrypted_file.dat"),
                "cipher": "extended_vigenere",
                "key": key,
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(dec_res.status_code, 200)
        self.assertEqual(dec_res.data, file_bytes)
        # Content-Disposition should restore original filename
        self.assertIn(filename, dec_res.headers.get("Content-Disposition", ""))


    # Test Error Handling
    def test_api_invalid_cipher(self):
        res = self.client.post("/api/encrypt/text", json={"cipher": "unknown_cipher", "plaintext": "ABC"})
        self.assertEqual(res.status_code, 400)
        self.assertIn("error", res.get_json()["status"])

    def test_api_hill_non_coprime_det(self):
        # Determinant non-coprime with 26
        payload = {
            "cipher": "hill",
            "plaintext": "HELP",
            "matrix": [[2, 4], [1, 2]],
        }
        res = self.client.post("/api/encrypt/text", json=payload)
        self.assertEqual(res.status_code, 400)
        self.assertIn("error", res.get_json()["status"])

    def test_api_file_crypto_super_encryption(self):
        filename = "dokumen_rahasia.docx"
        file_bytes = b"PK\x03\x04Dummy docx bytes \x99\x88\x77" * 20
        vkey = "VIGENEREPASS"
        tkey = "COLUMNKEY"

        # Encrypt File with Super Encryption
        enc_res = self.client.post(
            "/api/encrypt/file",
            data={
                "file": (io.BytesIO(file_bytes), filename),
                "cipher": "super_encryption",
                "key": vkey,
                "transposition_key": tkey,
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(enc_res.status_code, 200)

        # Decrypt File with Super Encryption
        dec_res = self.client.post(
            "/api/decrypt/file",
            data={
                "file": (io.BytesIO(enc_res.data), "encrypted_doc.dat"),
                "cipher": "super_encryption",
                "key": vkey,
                "transposition_key": tkey,
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(dec_res.status_code, 200)
        self.assertEqual(dec_res.data, file_bytes)
        self.assertIn(filename, dec_res.headers.get("Content-Disposition", ""))


if __name__ == "__main__":
    unittest.main()
