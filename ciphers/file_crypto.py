"""
File Cryptography Wrapper with Metadata Packet Header.
Embeds magic bytes 'KRIPTO', original filename length, and filename into
the payload before encryption.
Upon decryption, verifies header integrity and extracts the original filename
and extension so files (docx, pdf, jpg, mp4, db, etc.) are restored intact.
"""

import struct
from typing import Tuple, Union
from ciphers.vigenere_extended import ExtendedVigenereCipher
from ciphers.super_encryption import SuperEncryption

MAGIC_HEADER = b"KRIPTO"


class FileCrypto:
    """Wrapper for encrypting and decrypting arbitrary binary files with metadata headers."""

    def __init__(self):
        self.extended_vigenere = ExtendedVigenereCipher()
        self.super_encryption = SuperEncryption()

    @staticmethod
    def pack(filename: str, data: bytes) -> bytes:
        filename_bytes = filename.encode("utf-8")
        if len(filename_bytes) > 65535:
            raise ValueError("Filename is too long for header (max 65535 bytes).")
        header = MAGIC_HEADER + struct.pack(">H", len(filename_bytes)) + filename_bytes
        return header + data

    @staticmethod
    def unpack(packet: bytes) -> Tuple[str, bytes]:
        if not packet.startswith(MAGIC_HEADER):
            raise ValueError("Invalid ciphertext or corrupted header. Magic bytes 'KRIPTO' not found.")

        header_prefix_len = len(MAGIC_HEADER)
        if len(packet) < header_prefix_len + 2:
            raise ValueError("Corrupted packet: insufficient data length.")

        name_len = struct.unpack(">H", packet[header_prefix_len : header_prefix_len + 2])[0]
        name_end = header_prefix_len + 2 + name_len
        if len(packet) < name_end:
            raise ValueError("Corrupted packet: filename length exceeds packet size.")

        try:
            filename = packet[header_prefix_len + 2 : name_end].decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("Corrupted packet: unable to decode original filename.")

        data = packet[name_end:]
        return filename, data

    def encrypt_file(
        self,
        filename: str,
        data: bytes,
        cipher_type: str = "extended_vigenere",
        key: Union[str, bytes] = "",
        transposition_key: str = "",
    ) -> bytes:
        packed_data = self.pack(filename, data)
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key

        if cipher_type == "extended_vigenere":
            return self.extended_vigenere.encrypt_bytes(packed_data, key_bytes)
        elif cipher_type == "super_encryption":
            return self.super_encryption.encrypt(packed_data, key_bytes, transposition_key)
        else:
            raise ValueError(f"Unsupported file cipher type: {cipher_type}")

    def decrypt_file(
        self,
        encrypted_data: bytes,
        cipher_type: str = "extended_vigenere",
        key: Union[str, bytes] = "",
        transposition_key: str = "",
    ) -> Tuple[str, bytes]:
        key_bytes = key.encode("utf-8") if isinstance(key, str) else key

        if cipher_type == "extended_vigenere":
            decrypted_packet = self.extended_vigenere.decrypt_bytes(encrypted_data, key_bytes)
        elif cipher_type == "super_encryption":
            decrypted_packet = self.super_encryption.decrypt(encrypted_data, key_bytes, transposition_key)
        else:
            raise ValueError(f"Unsupported file cipher type: {cipher_type}")

        return self.unpack(decrypted_packet)
