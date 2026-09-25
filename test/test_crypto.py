"""
tests/test_crypto.py
=====================
Unit test otomatis untuk modul kdf.py dan crypto_core.py.

Cara menjalankan (dari folder root proyek, BUKAN dari dalam folder tests/):
    pytest tests/ -v

Kenapa file ini WAJIB ditaruh di folder "tests/" dengan nama diawali
"test_"? Karena itu adalah konvensi standar pytest untuk otomatis
menemukan (auto-discover) test tanpa perlu didaftarkan manual.
Begitu juga tiap fungsi di dalamnya HARUS diawali kata "test_" --
pytest mengenali pola nama ini untuk tahu mana yang harus dijalankan
sebagai test dan mana yang bukan.
"""

import os
import sys
import hashlib

# Supaya Python bisa menemukan modul di folder src/, kita tambahkan
# folder src ke "path pencarian modul" secara manual. Ini diperlukan
# karena tests/ dan src/ adalah folder yang berbeda level.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from crypto_core import (
    encrypt, decrypt, encrypt_to_base64, decrypt_from_base64,
    encrypt_file, decrypt_file, DekripsiGagalError,
    METODE_AES_GCM, METODE_CHACHA20,
)


# -----------------------------------------------------------------
# Fixture: data yang dipakai berulang di banyak test, supaya tidak
# copy-paste nilai yang sama di banyak tempat.
# -----------------------------------------------------------------
@pytest.fixture
def password_benar():
    return "passwordUjiCoba!2024"


@pytest.fixture
def pesan_contoh():
    return "Ini adalah pesan rahasia untuk keperluan pengujian.".encode("utf-8")


# ===================================================================
# TEST 1: Enkripsi lalu dekripsi harus mengembalikan data yang sama
# persis dengan aslinya (round-trip test). Ini test paling dasar --
# kalau ini gagal, seluruh sistem tidak bisa dipakai sama sekali.
# ===================================================================
def test_enkripsi_dekripsi_teks_berhasil(password_benar, pesan_contoh):
    paket = encrypt(pesan_contoh, password_benar)
    hasil = decrypt(paket, password_benar)
    assert hasil == pesan_contoh


# ===================================================================
# TEST 2: Dekripsi dengan password yang SALAH harus ditolak (melempar
# DekripsiGagalError), bukan malah mengembalikan data acak/rusak.
# ===================================================================
def test_dekripsi_password_salah_ditolak(password_benar, pesan_contoh):
    paket = encrypt(pesan_contoh, password_benar)
    password_salah = "passwordYangSalah"

    with pytest.raises(DekripsiGagalError):
        decrypt(paket, password_salah)


# ===================================================================
# TEST 3: Dekripsi dengan cipherteks yang sudah DIUBAH (walau cuma
# 1 byte) harus ditolak. Ini membuktikan mekanisme authentication tag
# AEAD berfungsi -- bukan cuma sekadar enkripsi biasa tanpa proteksi
# integritas.
# ===================================================================
def test_dekripsi_cipherteks_diubah_ditolak(password_benar, pesan_contoh):
    paket = encrypt(pesan_contoh, password_benar)

    # Ubah 1 byte terakhir dari paket (bagian cipherteks/tag)
    paket_rusak = bytearray(paket)
    paket_rusak[-1] ^= 0xFF  # balik semua bit di byte terakhir
    paket_rusak = bytes(paket_rusak)

    with pytest.raises(DekripsiGagalError):
        decrypt(paket_rusak, password_benar)


# ===================================================================
# TEST 4: Enkripsi dan dekripsi BERKAS harus menghasilkan file yang
# identik byte-per-byte dengan aslinya. Dibuktikan lewat perbandingan
# hash SHA-256, bukan cuma dibandingkan "kelihatannya sama".
# ===================================================================
def test_enkripsi_dekripsi_file_berhasil(tmp_path, password_benar):
    # tmp_path adalah fixture bawaan pytest: folder sementara yang
    # otomatis dibersihkan setelah test selesai, jadi tidak mengotori
    # folder proyek.
    file_asli = tmp_path / "contoh.txt"
    file_terenkripsi = tmp_path / "contoh.txt.enc"
    file_hasil = tmp_path / "contoh_hasil.txt"

    isi_asli = "Konten file uji coba untuk enkripsi berkas.\n" * 10
    file_asli.write_text(isi_asli, encoding="utf-8")

    encrypt_file(str(file_asli), str(file_terenkripsi), password_benar)
    decrypt_file(str(file_terenkripsi), str(file_hasil), password_benar)

    hash_asli = hashlib.sha256(file_asli.read_bytes()).hexdigest()
    hash_hasil = hashlib.sha256(file_hasil.read_bytes()).hexdigest()

    assert hash_asli == hash_hasil


# ===================================================================
# TEST 5: Kedua algoritma (AES-256-GCM dan ChaCha20-Poly1305) harus
# sama-sama berfungsi dengan benar, tidak cuma salah satu saja.
# ===================================================================
@pytest.mark.parametrize("metode", [METODE_AES_GCM, METODE_CHACHA20])
def test_kedua_algoritma_berfungsi(password_benar, pesan_contoh, metode):
    paket = encrypt(pesan_contoh, password_benar, metode=metode)
    hasil = decrypt(paket, password_benar)
    assert hasil == pesan_contoh


# ===================================================================
# TEST 6 (tambahan): Fungsi Base64 harus konsisten -- hasil enkripsi
# dalam bentuk teks Base64 bisa didekripsi kembali dengan benar.
# ===================================================================
def test_enkripsi_dekripsi_base64_berhasil(password_benar, pesan_contoh):
    teks_base64 = encrypt_to_base64(pesan_contoh, password_benar)
    hasil = decrypt_from_base64(teks_base64, password_benar)
    assert hasil == pesan_contoh


# ===================================================================
# TEST 7 (tambahan): Dua kali enkripsi pesan yang SAMA harus
# menghasilkan cipherteks yang BERBEDA (karena nonce acak tiap kali).
# Ini membuktikan nonce benar-benar acak, bukan tetap/statis --
# properti keamanan penting yang wajib diuji.
# ===================================================================
def test_nonce_selalu_berbeda_tiap_enkripsi(password_benar, pesan_contoh):
    paket_1 = encrypt(pesan_contoh, password_benar)
    paket_2 = encrypt(pesan_contoh, password_benar)

    # Meskipun pesan & password sama persis, hasil akhirnya harus beda
    assert paket_1 != paket_2

    # Tapi keduanya tetap harus bisa didekripsi balik dengan benar
    assert decrypt(paket_1, password_benar) == pesan_contoh
    assert decrypt(paket_2, password_benar) == pesan_contoh


# ===================================================================
# TEST 8 (tambahan): Enkripsi pesan kosong (edge case) tidak boleh
# menyebabkan crash -- harus tetap bisa dienkripsi dan didekripsi.
# ===================================================================
def test_enkripsi_pesan_kosong(password_benar):
    pesan_kosong = b""
    paket = encrypt(pesan_kosong, password_benar)
    hasil = decrypt(paket, password_benar)
    assert hasil == pesan_kosong