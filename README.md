# CipherForge — Web Engine Kriptografi Klasik & Modern
Proyek Ujian Tengah Semester (UTS) — Mata Kuliah Kriptografi  
Jurusan Informatika, Fakultas Teknik, Universitas Siliwangi

* **Nama Mahasiswa :** Friza Tri Maulana  
* **NPM            :** 237006125 (Kelas E)  
* **Dosen Pengampu :** Ir. Randi Rizal, Ph.D.  
* **Demo Aplikasi  :** [https://kripto.prizftm.my.id](https://kripto.prizftm.my.id)

---

## Deskripsi Singkat

CipherForge adalah aplikasi web pengujian kriptografi klasik dan modern yang dibangun menggunakan Python (Flask) dan JavaScript murni. Aplikasi ini dirancang untuk memproses enkripsi dan dekripsi pesan teks secara interaktif serta berkas biner sembarang (*arbitrary files*) tanpa merusak format berkas aslinya.

### Daftar Algoritma yang Tersedia:
1. **Standard Vigenère Cipher:** Substitusi polialfabetik 26 alfabet kapital (kunci diulang secara periodik).
2. **Auto-Key Vigenère Cipher:** Aliran kunci disambung dengan karakter plainteks asli untuk mencegah periodisitas Kasiski.
3. **Extended Vigenère Cipher:** Operasi modulo 256 pada ranah byte ASCII penuh (mendukung teks dan file biner).
4. **Playfair Cipher:** Substitusi digraf menggunakan matriks kunci 5×5 (penggabungan I/J, penyisipan karakter pengisi X/Z).
5. **Affine Cipher:** Substitusi linier $C = (a \cdot P + b) \bmod 26$ dengan verifikasi syarat koprima $\gcd(a, 26) = 1$.
6. **Hill Cipher:** Kriptografi poligram berbasis matriks ordo 2×2 dan 3×3 dengan invers determinan modular 26.
7. **Super Enkripsi:** Kombinasi rantai substitusi Extended Vigenère (256 byte) dan permutasi transposisi kolom.
8. **Enigma Machine M3 (Bonus):** Simulasi mesin sandi elektromekanis dengan 3 rotor berputar (I–V), Reflektor B/C, dan kabel penukar Plugboard (*Steckerbrett*).

---

## Fitur Utama

* **Dual-Mode Input:** Pemrosesan teks langsung dari keyboard dan unggah berkas biner sembarang (PDF, DOCX, PNG, JPG, MP3, MP4, DB).
* **Protokol Berkas `KRIPTO`:** Menyimpan nama dan format ekstensi asli berkas ke dalam header paket biner sehingga saat didekripsi berkas pulih 100% utuh.
* **Tiga Format Output:** Menampilkan cipherteks dalam bentuk teks alfabet, Base64, dan heksadesimal (Hex).
* **Validasi Matematis Real-Time:** Pengecekan nilai kunci tidak valid (invers determinan matriks Hill dan koprima Affine) langsung pada antarmuka.

---

## Cara Menjalankan

1. **Clone Repositori:**
   ```bash
   git clone https://github.com/friza13/uts-kriptografi.git
   cd uts-kriptografi
   ```

2. **Pasang Dependensi:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Jalankan Server:**
   ```bash
   python app.py
   ```

4. **Buka Browser:**
   Akses antarmuka web di:
   ```text
   http://localhost:5000
   ```
   atau melalui versi deployment server di:
   ```text
   https://kripto.prizftm.my.id
   ```
