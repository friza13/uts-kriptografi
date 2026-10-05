"""
Flask Web Server & REST API for UTS Kriptografi.
Student: Friza Tri Maulana (NIM: 237006125)
Institution: Universitas Siliwangi - Teknik Informatika
"""

import base64
import io
import mimetypes
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename

from ciphers.vigenere_standard import StandardVigenereCipher
from ciphers.vigenere_autokey import AutokeyVigenereCipher
from ciphers.vigenere_extended import ExtendedVigenereCipher
from ciphers.playfair import PlayfairCipher
from ciphers.affine import AffineCipher
from ciphers.hill import HillCipher
from ciphers.super_encryption import SuperEncryption
from ciphers.enigma import EnigmaM3
from ciphers.file_crypto import FileCrypto

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB max upload

# Initialize Cipher Instances
vigenere_std = StandardVigenereCipher()
vigenere_auto = AutokeyVigenereCipher()
vigenere_ext = ExtendedVigenereCipher()
playfair_cipher = PlayfairCipher()
affine_cipher = AffineCipher()
hill_cipher = HillCipher()
super_enc = SuperEncryption()
file_crypto = FileCrypto()


@app.route("/")
def index():
    student_info = {
        "name": "Friza Tri Maulana",
        "nim": "237006125",
        "course": "Kriptografi (3 SKS)",
        "lecturer": "Ir. Randi Rizal, Ph.D.",
        "class": "Informatika - Fakultas Teknik",
        "university": "Universitas Siliwangi",
        "academic_year": "2024/2025 (Genap)",
    }
    return render_template("index.html", student=student_info)


@app.route("/api/encrypt/text", methods=["POST"])
def encrypt_text():
    data = request.get_json() or {}
    cipher_type = data.get("cipher", "").strip()
    plaintext = data.get("plaintext", "")

    if not cipher_type:
        return jsonify({"status": "error", "message": "Cipher type is required."}), 400

    try:
        response_data = {
            "status": "success",
            "cipher": cipher_type,
            "plaintext": plaintext,
        }

        if cipher_type == "vigenere_standard":
            key = data.get("key", "")
            ciphertext = vigenere_std.encrypt(plaintext, key)

        elif cipher_type == "vigenere_autokey":
            key = data.get("key", "")
            ciphertext = vigenere_auto.encrypt(plaintext, key)

        elif cipher_type == "vigenere_extended":
            key = data.get("key", "")
            ciphertext = vigenere_ext.encrypt(plaintext, key)

        elif cipher_type == "playfair":
            key = data.get("key", "")
            ciphertext = playfair_cipher.encrypt(plaintext, key)
            response_data["matrix"] = playfair_cipher.generate_matrix(key)

        elif cipher_type == "affine":
            a = int(data.get("a", 1))
            b = int(data.get("b", 0))
            ciphertext = affine_cipher.encrypt(plaintext, a, b)
            response_data["a"] = a
            response_data["b"] = b

        elif cipher_type == "hill":
            matrix_input = data.get("matrix")
            if not matrix_input:
                raise ValueError("Hill cipher requires matrix or keyword key.")
            normalized_mat = hill_cipher.normalize_matrix(matrix_input)
            ciphertext = hill_cipher.encrypt(plaintext, normalized_mat)
            inv_mat = hill_cipher.invert_matrix(normalized_mat)
            det = hill_cipher.determinant(normalized_mat) % 26
            response_data["matrix"] = normalized_mat
            response_data["inv_matrix"] = inv_mat
            response_data["det"] = det

        elif cipher_type == "super_encryption":
            vkey = data.get("key", "")
            tkey = data.get("transposition_key", "")
            if not vkey or not tkey:
                raise ValueError("Super Encryption requires both Vigenere key and Transposition key.")
            ciphertext = super_enc.encrypt_text(plaintext, vkey, tkey)

        elif cipher_type == "enigma":
            rotors = data.get("rotors", ["I", "II", "III"])
            initial_pos = data.get("initial_positions", [0, 0, 0])
            reflector = data.get("reflector", "B")
            ring_settings = data.get("ring_settings", [0, 0, 0])
            plugboard = data.get("plugboard", "")

            enigma = EnigmaM3(
                rotors=rotors,
                reflector=reflector,
                ring_settings=ring_settings,
                initial_positions=initial_pos,
                plugboard=plugboard,
            )
            ciphertext = enigma.process_text(plaintext)
            response_data["end_positions"] = enigma.get_positions()

        else:
            return jsonify({"status": "error", "message": f"Unsupported cipher type: {cipher_type}"}), 400

        # Calculate base64 and hex representations
        ct_bytes = ciphertext.encode("latin-1")
        response_data["ciphertext"] = ciphertext
        response_data["base64"] = base64.b64encode(ct_bytes).decode("ascii")
        response_data["hex"] = ct_bytes.hex().upper()

        return jsonify(response_data)

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route("/api/decrypt/text", methods=["POST"])
def decrypt_text():
    data = request.get_json() or {}
    cipher_type = data.get("cipher", "").strip()
    ciphertext = data.get("ciphertext", "")
    input_format = data.get("input_format", "raw").lower()

    if not cipher_type:
        return jsonify({"status": "error", "message": "Cipher type is required."}), 400

    try:
        # Convert input format to standard string representation if needed
        if input_format == "base64" and ciphertext:
            try:
                ct_bytes = base64.b64decode(ciphertext.strip())
                ciphertext = ct_bytes.decode("latin-1")
            except Exception as e:
                return jsonify({"status": "error", "message": f"Invalid Base64 input: {str(e)}"}), 400
        elif input_format == "hex" and ciphertext:
            try:
                ct_bytes = bytes.fromhex(ciphertext.strip())
                ciphertext = ct_bytes.decode("latin-1")
            except Exception as e:
                return jsonify({"status": "error", "message": f"Invalid Hex input: {str(e)}"}), 400

        if cipher_type == "vigenere_standard":
            key = data.get("key", "")
            decrypted = vigenere_std.decrypt(ciphertext, key)

        elif cipher_type == "vigenere_autokey":
            key = data.get("key", "")
            decrypted = vigenere_auto.decrypt(ciphertext, key)

        elif cipher_type == "vigenere_extended":
            key = data.get("key", "")
            decrypted = vigenere_ext.decrypt(ciphertext, key)

        elif cipher_type == "playfair":
            key = data.get("key", "")
            decrypted = playfair_cipher.decrypt(ciphertext, key)

        elif cipher_type == "affine":
            a = int(data.get("a", 1))
            b = int(data.get("b", 0))
            decrypted = affine_cipher.decrypt(ciphertext, a, b)

        elif cipher_type == "hill":
            matrix_input = data.get("matrix")
            if not matrix_input:
                raise ValueError("Hill cipher requires matrix or keyword key.")
            normalized_mat = hill_cipher.normalize_matrix(matrix_input)
            decrypted = hill_cipher.decrypt(ciphertext, normalized_mat)

        elif cipher_type == "super_encryption":
            vkey = data.get("key", "")
            tkey = data.get("transposition_key", "")
            if not vkey or not tkey:
                raise ValueError("Super Encryption requires both Vigenere key and Transposition key.")
            decrypted = super_enc.decrypt_text(ciphertext, vkey, tkey)

        elif cipher_type == "enigma":
            rotors = data.get("rotors", ["I", "II", "III"])
            initial_pos = data.get("initial_positions", [0, 0, 0])
            reflector = data.get("reflector", "B")
            ring_settings = data.get("ring_settings", [0, 0, 0])
            plugboard = data.get("plugboard", "")

            enigma = EnigmaM3(
                rotors=rotors,
                reflector=reflector,
                ring_settings=ring_settings,
                initial_positions=initial_pos,
                plugboard=plugboard,
            )
            decrypted = enigma.process_text(ciphertext)

        else:
            return jsonify({"status": "error", "message": f"Unsupported cipher type: {cipher_type}"}), 400

        return jsonify({"status": "success", "cipher": cipher_type, "decrypted": decrypted})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route("/api/encrypt/file", methods=["POST"])
def encrypt_file_route():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"status": "error", "message": "No file selected."}), 400

    cipher_type = request.form.get("cipher", "extended_vigenere")
    key = request.form.get("key", "")
    transposition_key = request.form.get("transposition_key", "")

    if not key:
        return jsonify({"status": "error", "message": "Key is required for file encryption."}), 400

    try:
        raw_bytes = file.read()
        orig_filename = secure_filename(file.filename) or "file.bin"

        encrypted_packet = file_crypto.encrypt_file(
            filename=orig_filename,
            data=raw_bytes,
            cipher_type=cipher_type,
            key=key,
            transposition_key=transposition_key,
        )

        out_name = f"{orig_filename}.dat"
        return send_file(
            io.BytesIO(encrypted_packet),
            as_attachment=True,
            download_name=out_name,
            mimetype="application/octet-stream",
        )

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route("/api/decrypt/file", methods=["POST"])
def decrypt_file_route():
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"status": "error", "message": "No file selected."}), 400

    cipher_type = request.form.get("cipher", "extended_vigenere")
    key = request.form.get("key", "")
    transposition_key = request.form.get("transposition_key", "")

    if not key:
        return jsonify({"status": "error", "message": "Key is required for file decryption."}), 400

    try:
        encrypted_bytes = file.read()
        orig_filename, decrypted_data = file_crypto.decrypt_file(
            encrypted_data=encrypted_bytes,
            cipher_type=cipher_type,
            key=key,
            transposition_key=transposition_key,
        )

        guessed_mimetype = mimetypes.guess_type(orig_filename)[0] or "application/octet-stream"

        return send_file(
            io.BytesIO(decrypted_data),
            as_attachment=True,
            download_name=orig_filename,
            mimetype=guessed_mimetype,
        )

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
