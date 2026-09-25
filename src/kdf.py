"""
kdf.py
======
Modul untuk menurunkan (derive) kunci kriptografis dari password yang
diketik manusia. Password biasa itu lemah dan panjangnya tidak tentu,
sedangkan AES-256 butuh kunci acak sepanjang tepat 32 byte (256 bit).

KDF (Key Derivation Function) menyelesaikan masalah ini dengan cara
"menghajar" password berulang kali lewat fungsi hash, sehingga:
  1. Brute-force jadi lambat (setiap percobaan makan waktu/komputasi)
  2. Password sama + salt beda => kunci yang dihasilkan tetap beda
  3. Hasilnya selalu punya panjang tepat 32 byte, siap dipakai AES-256

Tersedia dua pilihan:
  - PBKDF2  : standar lama, cepat, cukup aman, didukung langsung oleh
              pustaka 'cryptography' tanpa dependensi tambahan
  - Argon2id: standar modern (pemenang Password Hashing Competition),
              lebih tahan terhadap serangan GPU/ASIC, butuh pustaka
              tambahan 'argon2-cffi'

Gunakan salah satu saja secara konsisten di seluruh aplikasi. Argon2id
lebih disarankan untuk aplikasi baru, tapi PBKDF2 tetap valid dan lebih
sederhana untuk dijelaskan di laporan.
"""

import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Coba import argon2-cffi; kalau belum terinstall, Argon2 tidak bisa
# dipakai tapi PBKDF2 tetap jalan normal.
try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_TERSEDIA = True
except ImportError:
    ARGON2_TERSEDIA = False

# ---------------------------------------------------------------------
# Konstanta
# ---------------------------------------------------------------------
UKURAN_SALT = 16          # byte, sesuai rekomendasi umum (128 bit)
UKURAN_KUNCI = 32         # byte = 256 bit, pas untuk AES-256
PBKDF2_ITERASI = 480_000  # rekomendasi OWASP 2023 untuk SHA-256

# Parameter Argon2id (nilai wajar untuk aplikasi desktop/web biasa,
# bukan server dengan traffic sangat tinggi)
ARGON2_TIME_COST = 3        # jumlah putaran
ARGON2_MEMORY_COST = 65536  # dalam KiB => 64 MB
ARGON2_PARALLELISM = 4      # jumlah thread paralel


def generate_salt() -> bytes:
    """
    Membangkitkan salt acak secara kriptografis.

    Salt WAJIB acak dan WAJIB berbeda setiap kali enkripsi baru
    dilakukan, meskipun password yang dipakai sama persis. Salt tidak
    perlu dirahasiakan -- ia akan disimpan bersama cipherteks agar bisa
    dipakai ulang saat proses dekripsi (menurunkan kunci yang sama).
    """
    return os.urandom(UKURAN_SALT)


def derive_key_pbkdf2(password: str, salt: bytes,
                       iterasi: int = PBKDF2_ITERASI) -> bytes:
    """
    Menurunkan kunci 256-bit dari password memakai PBKDF2-HMAC-SHA256.

    Parameters
    ----------
    password : str
        Password yang diketik pengguna.
    salt : bytes
        Salt acak (biasanya hasil generate_salt()).
    iterasi : int
        Jumlah putaran hashing. Semakin besar, semakin lambat di-brute-
        force tapi juga semakin lambat dipakai pengguna sah. 480.000
        adalah rekomendasi OWASP untuk SHA-256 per 2023.

    Returns
    -------
    bytes
        Kunci sepanjang 32 byte, siap dipakai AES-256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=UKURAN_KUNCI,
        salt=salt,
        iterations=iterasi,
    )
    return kdf.derive(password.encode("utf-8"))


def derive_key_argon2(password: str, salt: bytes) -> bytes:
    """
    Menurunkan kunci 256-bit dari password memakai Argon2id.

    Argon2id lebih modern dan lebih tahan serangan hardware khusus
    (GPU/ASIC) dibanding PBKDF2, karena ia juga "lapar memori"
    (memory-hard), bukan cuma lapar komputasi.

    Membutuhkan pustaka tambahan: pip install argon2-cffi
    """
    if not ARGON2_TERSEDIA:
        raise RuntimeError(
            "Pustaka argon2-cffi belum terinstall. "
            "Jalankan: pip install argon2-cffi"
        )

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=UKURAN_KUNCI,
        type=Type.ID,  # Argon2id, varian yang direkomendasikan umum
    )


def derive_key(password: str, salt: bytes, metode: str = "pbkdf2") -> bytes:
    """
    Fungsi pembungkus (wrapper) supaya crypto_core.py cukup memanggil
    satu fungsi ini tanpa perlu tahu detail PBKDF2 vs Argon2.

    Parameters
    ----------
    metode : str
        "pbkdf2" atau "argon2"
    """
    if metode == "pbkdf2":
        return derive_key_pbkdf2(password, salt)
    elif metode == "argon2":
        return derive_key_argon2(password, salt)
    else:
        raise ValueError(f"Metode KDF tidak dikenal: {metode}")


# ---------------------------------------------------------------------
# Blok ini hanya jalan kalau file di-run langsung (bukan di-import),
# berguna untuk tes cepat manual tanpa harus bikin file test terpisah.
# ---------------------------------------------------------------------
if __name__ == "__main__":
    password = "passwordSayaSangatRahasia123"
    salt = generate_salt()

    kunci_pbkdf2 = derive_key(password, salt, metode="pbkdf2")
    print(f"Salt (hex)          : {salt.hex()}")
    print(f"Kunci PBKDF2 (hex)  : {kunci_pbkdf2.hex()}")
    print(f"Panjang kunci       : {len(kunci_pbkdf2)} byte "
          f"({len(kunci_pbkdf2) * 8} bit)")

    # Buktikan sifat KDF: password sama + salt sama = kunci sama selalu
    kunci_pbkdf2_ulang = derive_key(password, salt, metode="pbkdf2")
    assert kunci_pbkdf2 == kunci_pbkdf2_ulang
    print("Konsistensi OK: password+salt sama menghasilkan kunci sama.")

    # Buktikan: salt beda -> kunci beda, walau password sama persis
    salt_lain = generate_salt()
    kunci_beda = derive_key(password, salt_lain, metode="pbkdf2")
    assert kunci_pbkdf2 != kunci_beda
    print("Uji salt OK: salt berbeda menghasilkan kunci yang berbeda.")

    if ARGON2_TERSEDIA:
        kunci_argon2 = derive_key(password, salt, metode="argon2")
        print(f"Kunci Argon2 (hex)  : {kunci_argon2.hex()}")
    else:
        print("Argon2 dilewati (pustaka argon2-cffi belum terinstall).")