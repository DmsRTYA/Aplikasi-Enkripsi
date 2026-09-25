"""
crypto_core.py
anjay
===============
Modul inti untuk enkripsi dan dekripsi data (teks maupun berkas biner)
memakai algoritma AEAD (Authenticated Encryption with Associated Data):
AES-256-GCM dan ChaCha20-Poly1305.

Kenapa AEAD, bukan enkripsi biasa?
----------------------------------
AEAD tidak cuma merahasiakan isi pesan, tapi juga membubuhkan sebuah
"authentication tag" hasil komputasi dari kunci + data. Saat dekripsi,
tag ini dicocokkan ulang. Kalau cipherteks/nonce diubah walau cuma
1 byte, tag tidak akan cocok dan dekripsi DITOLAK TOTAL -- inilah
mekanisme di balik syarat "menolak dekripsi bila cipherteks diubah".

Format paket terenkripsi
-------------------------
Supaya dekripsi tahu persis cara membongkar data, setiap hasil enkripsi
digabung dalam urutan tetap:

    [ 1 byte metode ][ 16 byte salt ][ 12 byte nonce ][ cipherteks+tag ]

- metode  : penanda algoritma apa yang dipakai (0 = AES-GCM,
            1 = ChaCha20-Poly1305), supaya dekripsi tahu cara membongkar
- salt    : dipakai ulang untuk menurunkan kunci yang sama saat dekripsi
- nonce   : WAJIB acak & unik setiap enkripsi (12 byte adalah ukuran
            standar untuk kedua algoritma ini)
- cipherteks+tag : tag otentikasi otomatis "menempel" di ujung
            cipherteks oleh pustaka 'cryptography', tidak perlu
            dipisah manual
"""

import os
import sys
import base64
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from kdf import generate_salt, derive_key

# ---------------------------------------------------------------------
# Konstanta
# ---------------------------------------------------------------------
UKURAN_NONCE = 12  # byte, standar untuk AES-GCM maupun ChaCha20-Poly1305

METODE_AES_GCM = 0
METODE_CHACHA20 = 1

_NAMA_METODE = {
    METODE_AES_GCM: "AES-256-GCM",
    METODE_CHACHA20: "ChaCha20-Poly1305",
}


class DekripsiGagalError(Exception):
    """
    Exception khusus yang dilempar saat dekripsi gagal, entah karena
    password salah ATAU karena cipherteks telah diubah/rusak.

    Sengaja tidak dibedakan pesannya menjadi "password salah" vs "data
    diubah" -- keduanya bermuara pada kegagalan verifikasi tag yang
    sama, dan membedakan pesan error ke pengguna justru bisa membuka
    celah informasi bagi penyerang (oracle attack).
    """
    pass


def _pilih_algoritma(metode: int, kunci: bytes):
    """Mengembalikan objek cipher AEAD yang sesuai dengan kode metode."""
    if metode == METODE_AES_GCM:
        return AESGCM(kunci)
    elif metode == METODE_CHACHA20:
        return ChaCha20Poly1305(kunci)
    else:
        raise ValueError(f"Kode metode tidak dikenal: {metode}")


def encrypt(plaintext: bytes, password: str,
            metode: int = METODE_AES_GCM) -> bytes:
    """
    Mengenkripsi data mentah (bytes) memakai password.

    Parameters
    ----------
    plaintext : bytes
        Data asli yang mau dirahasiakan. Untuk teks, encode dulu ke
        bytes (mis. teks.encode("utf-8")). Untuk berkas, cukup baca
        isinya dalam mode "rb".
    password : str
        Password yang dipakai pengguna untuk enkripsi.
    metode : int
        METODE_AES_GCM (default) atau METODE_CHACHA20.

    Returns
    -------
    bytes
        Paket terenkripsi utuh: metode + salt + nonce + cipherteks.
        Bisa langsung disimpan ke file, atau di-encode Base64 dulu
        lewat encrypt_to_base64() kalau mau ditampilkan sebagai teks.
    """
    salt = generate_salt()
    kunci = derive_key(password, salt, metode="pbkdf2")
    nonce = os.urandom(UKURAN_NONCE)

    cipher = _pilih_algoritma(metode, kunci)
    # Parameter ketiga (None) adalah "associated data" -- data tambahan
    # yang ikut diautentikasi tapi tidak dienkripsi. Tidak dipakai di
    # sini, jadi None.
    cipherteks = cipher.encrypt(nonce, plaintext, None)

    paket = bytes([metode]) + salt + nonce + cipherteks
    return paket


def decrypt(paket: bytes, password: str) -> bytes:
    """
    Mendekripsi paket hasil encrypt() kembali menjadi plaintext asli.

    Akan melempar DekripsiGagalError jika:
      - password yang dimasukkan salah, ATAU
      - paket (nonce/cipherteks/tag) telah diubah/rusak

    PENTING: fungsi ini TIDAK PERNAH mengembalikan hasil dekripsi
    parsial/rusak. Kalau verifikasi tag gagal, exception dilempar dan
    tidak ada data yang dikembalikan sama sekali.
    """
    try:
        metode = paket[0]
        salt = paket[1:17]                    # 16 byte setelah metode
        nonce = paket[17:17 + UKURAN_NONCE]    # 12 byte berikutnya
        cipherteks = paket[17 + UKURAN_NONCE:]  # sisanya

        kunci = derive_key(password, salt, metode="pbkdf2")
        cipher = _pilih_algoritma(metode, kunci)

        plaintext = cipher.decrypt(nonce, cipherteks, None)
        return plaintext

    except InvalidTag:
        # Ini kasus paling umum: password salah atau data diubah
        raise DekripsiGagalError(
            "Dekripsi gagal: password salah atau data telah diubah."
        )
    except (IndexError, ValueError) as e:
        # Paket terlalu pendek/rusak strukturnya (bukan sekadar tag)
        raise DekripsiGagalError(f"Paket data tidak valid: {e}")


# ---------------------------------------------------------------------
# Fungsi bantu untuk tampilan teks (Base64), sesuai fitur wajib:
# "cipherteks dapat ditampilkan dan disalin dalam format Base64"
# ---------------------------------------------------------------------

def encrypt_to_base64(plaintext: bytes, password: str,
                       metode: int = METODE_AES_GCM) -> str:
    """Enkripsi lalu langsung encode hasilnya jadi string Base64."""
    paket = encrypt(plaintext, password, metode)
    return base64.b64encode(paket).decode("ascii")


def decrypt_from_base64(teks_base64: str, password: str) -> bytes:
    """Decode string Base64 kembali ke paket bytes, lalu dekripsi."""
    paket = base64.b64decode(teks_base64)
    return decrypt(paket, password)


# ---------------------------------------------------------------------
# Fungsi untuk berkas (file), sesuai fitur wajib "enkripsi teks maupun
# berkas". Fungsi ini tinggal membaca/menulis bytes dari/ke disk lalu
# memanggil encrypt()/decrypt() yang sama persis dengan yang dipakai
# untuk teks -- karena bagi AES, teks dan berkas sama-sama cuma bytes.
# ---------------------------------------------------------------------

def encrypt_file(path_asal: str, path_tujuan: str, password: str,
                  metode: int = METODE_AES_GCM) -> None:
    """Membaca berkas apa pun, mengenkripsinya, menyimpan hasilnya."""
    with open(path_asal, "rb") as f:
        data_asli = f.read()

    paket = encrypt(data_asli, password, metode)

    with open(path_tujuan, "wb") as f:
        f.write(paket)


def decrypt_file(path_asal: str, path_tujuan: str, password: str) -> None:
    """Membaca berkas terenkripsi, mendekripsinya, menyimpan hasilnya."""
    with open(path_asal, "rb") as f:
        paket = f.read()

    data_asli = decrypt(paket, password)  # bisa lempar DekripsiGagalError

    with open(path_tujuan, "wb") as f:
        f.write(data_asli)


# ---------------------------------------------------------------------
# ANTARMUKA INTERAKTIF (CLI)
# =========================
# Bagian ini yang dijalankan saat Anda run "python src/crypto_core.py".
# Berbeda dari versi sebelumnya, di sini SEMUA nilai (password, pesan,
# pilihan algoritma) diminta langsung dari Anda lewat terminal, bukan
# nilai contoh yang sudah ditulis di kode (hardcoded).
# ---------------------------------------------------------------------

def _pilih_metode_dari_input() -> int:
    """Menanyakan ke user mau pakai algoritma yang mana."""
    print("Pilih algoritma:")
    print("  1. AES-256-GCM (default)")
    print("  2. ChaCha20-Poly1305")
    pilihan = input("Masukkan pilihan [1/2, kosongkan untuk default]: ").strip()
    if pilihan == "2":
        return METODE_CHACHA20
    return METODE_AES_GCM


def _input_password(prompt: str = "Masukkan password: ") -> str:
    """
    Meminta password tanpa menampilkannya di layar (memakai getpass).
    Kalau terminal tidak mendukung getpass (misal dijalankan dari
    beberapa IDE), otomatis jatuh ke input() biasa supaya tidak crash.
    """
    try:
        return getpass.getpass(prompt)
    except Exception:
        print("(Peringatan: password akan terlihat di layar)")
        return input(prompt)


def menu_enkripsi_teks() -> None:
    print("\n--- Enkripsi Teks ---")
    pesan = input("Masukkan pesan yang mau dienkripsi: ")
    password = _input_password("Buat password untuk enkripsi ini: ")
    if password == "":
        print("Password tidak boleh kosong. Dibatalkan.\n")
        return

    metode = _pilih_metode_dari_input()

    hasil_base64 = encrypt_to_base64(pesan.encode("utf-8"), password, metode)

    print(f"\nBerhasil dienkripsi dengan {_NAMA_METODE[metode]}.")
    print("Cipherteks (Base64), simpan/salin ini untuk didekripsi nanti:")
    print(hasil_base64)
    print()


def menu_dekripsi_teks() -> None:
    print("\n--- Dekripsi Teks ---")
    teks_base64 = input("Tempelkan cipherteks (Base64): ").strip()
    password = _input_password("Masukkan password: ")

    try:
        hasil = decrypt_from_base64(teks_base64, password)
        print("\nDekripsi berhasil. Pesan asli:")
        print(hasil.decode("utf-8"))
    except DekripsiGagalError as e:
        print(f"\nGAGAL: {e}")
    except Exception as e:
        print(f"\nGAGAL: format cipherteks tidak valid ({e})")
    print()


def menu_enkripsi_file() -> None:
    print("\n--- Enkripsi Berkas ---")
    path_asal = input("Path berkas yang mau dienkripsi: ").strip()

    if not os.path.isfile(path_asal):
        print(f"Berkas tidak ditemukan: {path_asal}\n")
        return

    path_tujuan = input(
        "Path untuk menyimpan hasil (contoh: rahasia.pdf.enc): "
    ).strip()
    password = _input_password("Buat password untuk enkripsi ini: ")
    if password == "":
        print("Password tidak boleh kosong. Dibatalkan.\n")
        return

    metode = _pilih_metode_dari_input()

    try:
        encrypt_file(path_asal, path_tujuan, password, metode)
        ukuran = os.path.getsize(path_tujuan)
        print(f"\nBerhasil. Berkas terenkripsi disimpan di: {path_tujuan}")
        print(f"Ukuran berkas hasil: {ukuran} byte\n")
    except Exception as e:
        print(f"\nGAGAL mengenkripsi berkas: {e}\n")


def menu_dekripsi_file() -> None:
    print("\n--- Dekripsi Berkas ---")
    path_asal = input("Path berkas terenkripsi (.enc): ").strip()

    if not os.path.isfile(path_asal):
        print(f"Berkas tidak ditemukan: {path_asal}\n")
        return

    path_tujuan = input("Path untuk menyimpan hasil dekripsi: ").strip()
    password = _input_password("Masukkan password: ")

    try:
        decrypt_file(path_asal, path_tujuan, password)
        print(f"\nBerhasil. Berkas hasil dekripsi disimpan di: {path_tujuan}\n")
    except DekripsiGagalError as e:
        print(f"\nGAGAL: {e}\n")
    except Exception as e:
        print(f"\nGAGAL: {e}\n")


def tampilkan_menu() -> None:
    print("=" * 50)
    print("   APLIKASI ENKRIPSI - Keamanan Informasi")
    print("=" * 50)
    print("1. Enkripsi teks")
    print("2. Dekripsi teks")
    print("3. Enkripsi berkas")
    print("4. Dekripsi berkas")
    print("5. Keluar")


def main() -> None:
    aksi = {
        "1": menu_enkripsi_teks,
        "2": menu_dekripsi_teks,
        "3": menu_enkripsi_file,
        "4": menu_dekripsi_file,
    }

    while True:
        tampilkan_menu()
        pilihan = input("Pilih menu (1-5): ").strip()

        if pilihan == "5":
            print("Keluar dari aplikasi. Sampai jumpa!")
            sys.exit(0)

        fungsi = aksi.get(pilihan)
        if fungsi is None:
            print("Pilihan tidak dikenal, coba lagi.\n")
            continue

        fungsi()


if __name__ == "__main__":
    main()