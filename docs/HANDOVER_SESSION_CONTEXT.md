# HANDOVER SESSION CONTEXT — UTS KRIPTOGRAFI

## Project Identity
- Project: Aplikasi Web Kriptografi Klasik & Modern (Tugas Project-Based UTS)
- Repository: `https://github.com/friza13/uts-kriptografi`
- Local Path: `/home/priz/Documents/tugas kampus/kriptografi/uts`
- Student: Friza Tri Maulana (NIM: 237006125)
- OpenCode Active Session: `ses_ef40fb4f9ffeafWhK6ZukYYWle`

## Rules & Constraints
1. **Academic Student Code Quality:** Natural Python 3 code with Flask. No AI slop or overcomplicated patterns.
2. **Confidentiality:** All prompt and internal planning files live in `docs/internal/` (which is gitignored and excluded from student submission ZIP).
3. **Algorithms Required:**
   - Vigenere Standard (26 alphabet)
   - Auto-Key Vigenere (26 alphabet)
   - Extended Vigenere (256 ASCII / full byte binary)
   - Playfair Cipher (26 alphabet, 5x5 matrix, I/J merged)
   - Affine Cipher (26 alphabet, gcd(a,26)=1)
   - Hill Cipher (26 alphabet, 2x2 and 3x3 matrices)
   - Super Encryption (Extended Vigenere + Columnar Transposition)
   - Bonus 1: Enigma Cipher M3 (3 rotors, reflector B, plugboard)
4. **Key Features:**
   - Dual Input: Text (keyboard) & Binary Files (any file type: txt, docx, pdf, png, jpg, mp3, mp4, db).
   - Binary Packet Metadata Header: Stores original filename and extension so decryption restores original file intact.
   - Output representations: Raw alphabet, Base64, Hexadecimal.
   - Save / Download ciphertext as binary/dat file.
5. **Git Protocol:** Atomic commit per phase, push to GitHub origin main.

## Development Progress
- **Phase 1 (Completed):**
  - Modular implementations for all 8 ciphers:
    1. `ciphers/vigenere_standard.py`: Standard Vigenere (26 letters, non-alpha stripped)
    2. `ciphers/vigenere_autokey.py`: Auto-Key Vigenere (26 letters, plaintext autokey)
    3. `ciphers/vigenere_extended.py`: Extended Vigenere (256 ASCII / full byte-by-byte)
    4. `ciphers/playfair.py`: Playfair Cipher (5x5 matrix, I/J merged, duplicate & padding rules)
    5. `ciphers/affine.py`: Affine Cipher (mod 26, coprime validation, Extended Euclidean algorithm)
    6. `ciphers/hill.py`: Hill Cipher (2x2 and 3x3 matrices, coprime determinant validation, adjugate inversion)
    7. `ciphers/super_encryption.py`: Super Encryption (Extended Vigenere 256 + Irregular Columnar Transposition)
    8. `ciphers/enigma.py`: Enigma M3 Machine (Rotors I-V, Reflector B/C, Plugboard, double-stepping)
    9. `ciphers/file_crypto.py`: Binary file wrapper with KRIPTO magic header and filename preservation
  - Unit tests: `tests/test_ciphers.py` (38/38 passing, 100% green)
- **Phase 2 (Pending):** Flask Web UI and Endpoints

