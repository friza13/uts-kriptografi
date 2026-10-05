# APLIKASI WEB KRIPTOGRAFI KLASIK & MODERN
**Tugas Project-Based Ujian Tengah Semester (UTS) — Mata Kuliah Kriptografi**  
Program Studi Informatika, Fakultas Teknik, Universitas Siliwangi (2024/2025)

* **Nama Mahasiswa :** Friza Tri Maulana  
* **NIM            :** 237006125 (Kelas A)  
* **Dosen Pengampu :** Ir. Randi Rizal, Ph.D.  
* **Repositori     :** [https://github.com/friza13/uts-kriptografi](https://github.com/friza13/uts-kriptografi)

---

## 1. Deskripsi Aplikasi

Aplikasi ini merupakan perangkat lunak berbasis web mandiri (*self-hosted web application*) yang dibangun menggunakan **Python 3** dan framework **Flask**. Aplikasi ini menyediakan antarmuka terpadu untuk pengujian enkripsi dan dekripsi pesan teks serta berkas sembarang (*arbitrary binary files*) menggunakan algoritma kriptografi klasik dan kombinasinya.

### Algoritma yang Diimplementasikan:
1. **Standard Vigenère Cipher:** Substitusi polialfabetik 26 alfabet kapital tanpa spasi.
2. **Auto-Key Vigenère Cipher:** Aliran kunci berlanjut menggunakan karakter plainteks asli.
3. **Extended Vigenère Cipher:** Operasi byte-by-byte pada ranah 256 ASCII (mendukung teks dan file biner).
4. **Playfair Cipher:** Matriks $5 \times 5$ dengan penggabungan huruf I/J, penyisipan karakter pengisi (X/Z), dan pembentukan bigram.
5. **Affine Cipher:** Substitusi linier $C = (a \cdot P + b) \bmod 26$ dengan validasi matematis $\gcd(a, 26) = 1$ serta invers modulo via *Extended Euclidean Algorithm*.
6. **Hill Cipher:** Kriptosistem matriks $2 \times 2$ dan $3 \times 3$ dengan validasi determinan koprima terhadap 26 dan matriks balikan modular (*adjugate inverse matrix*).
7. **Super Enkripsi:** Kombinasi bertingkat antara *Extended Vigenère Cipher* (substitusi) dan *Columnar Transposition Cipher* (transposisi kolom beraturan/tak beraturan).
8. **Enigma Cipher (Bonus 1):** Simulasi mesin sandi Enigma M3 (3 Rotor I–V, Reflector B/C, Plugboard, dan *stepping mechanism*).

---

## 2. Fitur Unggulan Sistem

* **Dukungan Berkas Biner Universal (*Any File Type*):**  
  Mampu mengenkripsi seluruh byte berkas (termasuk *header* berkas) sehingga berkas terenkripsi tidak dapat dibuka oleh aplikasi pemutarnya sebelum didekripsi kembali.
* **Preservasi Metadata Ekstensi (*Self-Describing Packet Header*):**  
  Menyisipkan *header* aman 8-byte (`KRIPTO`) yang memuat nama dan format ekstensi asli berkas (misal `.docx`, `.pdf`, `.jpg`, `.mp3`, `.mp4`, `.db`). Saat didekripsi, berkas otomatis dipulihkan ke nama dan format aslinya tanpa risiko korupsi.
* **Representasi Output Ganda:**  
  Hasil cipherteks teks dapat ditampilkan dalam bentuk **Raw Alphabet** (rapat tanpa spasi), **Base64**, dan **Heksadesimal (Hex)**.
* **Visualisasi Edukatif Real-Time:**  
  Menampilkan tabel matriks $5 \times 5$ Playfair, matriks kunci beserta balikan modulo Hill Cipher, serta pergeseran rotor Enigma.
* **Dukungan Uji Otomatis:**  
  Dilengkapi rangkaian *unit test* dan *integration test* lengkap (52 skenario pengujian, 100% *pass*).

---

## 3. Panduan Instalasi & Eksekusi

### Kebutuhan Sistem:
* Python 3.9+ (disarankan Python 3.10 ke atas)
* Web Browser modern (Chrome, Chromium, Firefox, Edge)

### Langkah Menjalankan:

1. **Clone Repositori:**
   ```bash
   git clone https://github.com/friza13/uts-kriptografi.git
   cd uts-kriptografi
   ```

2. **Pasang Dependensi:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Jalankan Aplikasi:**
   ```bash
   python app.py
   ```

4. **Akses Antarmuka Web:**  
   Buka peramban (*web browser*) dan navigasikan ke:
   ```text
   http://localhost:5000
   ```

---

## 4. Menjalankan Rangkaian Uji Otomatis (*Automated Tests*)

Untuk memverifikasi kebenaran algoritma dan rute web, jalankan perintah:
```bash
python -m unittest discover tests -v
```

---

## 5. Tabel Evaluasi Keberhasilan Spek

| No | Spesifikasi Fitur Soal | Status | Keterangan Teknis |
|:---:|:---|:---:|:---|
| 1 | Vigenère Cipher Standard (26 Alfabet) | **Berhasil (✓)** | Sanitasi alfabet, enkripsi/dekripsi akurat, tanpa spasi. |
| 2 | Auto-Key Vigenère Cipher (26 Alfabet) | **Berhasil (✓)** | Aliran kunci plainteks berjalan presisi, resiprokal 100%. |
| 3 | Extended Vigenère Cipher (256 ASCII) | **Berhasil (✓)** | Mendukung teks berkarakter bebas dan berkas biner penuh. |
| 4 | Playfair Cipher (26 Alfabet) | **Berhasil (✓)** | Matriks $5 \times 5$, aturan I/J, pemisah huruf ganda X/Z. |
| 5 | Affine Cipher (26 Alfabet) | **Berhasil (✓)** | Formula modulo 26, validasi koprima $\gcd(a, 26)=1$. |
| 6 | Hill Cipher (26 Alfabet) | **Berhasil (✓)** | Matriks $2 \times 2$ dan $3 \times 3$, invers modular adjugate. |
| 7 | Super Enkripsi (Extended + Transposisi) | **Berhasil (✓)** | Kombinasi substitusi 256 dan transposisi kolom biner. |
| 8 | (Bonus 1) Enigma Cipher | **Berhasil (✓)** | Simulasi Enigma M3 (Rotor, Reflector B, Plugboard). |
| 9 | (Bonus 2) Bahasa Pemrograman | **Dialihkan** | Dibangun menggunakan Python (Flask) untuk stabilitas platform. |
