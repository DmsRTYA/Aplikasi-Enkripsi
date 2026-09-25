"""
crypto_core.py
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
import base64
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
# Blok tes manual cepat -- jalankan langsung: python src/crypto_core.py
# ---------------------------------------------------------------------
if __name__ == "__main__":
    password_benar = "kataSandiSaya!2024"
    password_salah = "kataSandiSalah"
    pesan_asli = "Halo, ini pesan rahasia yang harus tetap aman.".encode("utf-8")

    print("=== Uji dasar: enkripsi lalu dekripsi dengan password benar ===")
    paket = encrypt(pesan_asli, password_benar, metode=METODE_AES_GCM)
    print(f"Ukuran paket terenkripsi : {len(paket)} byte")
    print(f"Metode dipakai           : {_NAMA_METODE[paket[0]]}")

    hasil = decrypt(paket, password_benar)
    assert hasil == pesan_asli
    print(f"Dekripsi berhasil        : {hasil.decode('utf-8')}")

    print("\n=== Uji tampilan Base64 ===")
    teks_b64 = encrypt_to_base64(pesan_asli, password_benar)
    print(f"Cipherteks (Base64)      : {teks_b64[:60]}...")
    hasil_b64 = decrypt_from_base64(teks_b64, password_benar)
    assert hasil_b64 == pesan_asli
    print("Dekripsi dari Base64 berhasil.")

    print("\n=== Uji penolakan: password salah ===")
    try:
        decrypt(paket, password_salah)
        print("BUG: seharusnya gagal tapi malah berhasil!")
    except DekripsiGagalError as e:
        print(f"Ditolak dengan benar     : {e}")

    print("\n=== Uji penolakan: cipherteks diubah 1 byte ===")
    paket_rusak = bytearray(paket)
    paket_rusak[-1] ^= 0xFF  # balik semua bit di byte terakhir
    try:
        decrypt(bytes(paket_rusak), password_benar)
        print("BUG: seharusnya gagal tapi malah berhasil!")
    except DekripsiGagalError as e:
        print(f"Ditolak dengan benar     : {e}")

    print("\n=== Uji algoritma kedua: ChaCha20-Poly1305 ===")
    paket_chacha = encrypt(pesan_asli, password_benar, metode=METODE_CHACHA20)
    hasil_chacha = decrypt(paket_chacha, password_benar)
    assert hasil_chacha == pesan_asli
    print(f"Dekripsi ChaCha20 berhasil: {hasil_chacha.decode('utf-8')}")

    print("\nSemua uji manual berhasil dijalankan.")