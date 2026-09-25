"""
pengujian/uji_kebenaran.py
===========================
PENGUJIAN WAJIB #2: Kebenaran dekripsi pada minimal 10 masukan berbeda,
termasuk berkas gambar dan PDF.

Konsep
------
Test ini membuktikan aplikasi bekerja BENAR untuk berbagai jenis data,
bukan cuma untuk 1 contoh teks pendek yang kebetulan berhasil. Caranya:

  1. Kumpulkan >= 10 data uji yang BERBEDA jenis/ukuran/isi
  2. Enkripsi tiap data, lalu dekripsi lagi
  3. Bandingkan hash SHA-256 SEBELUM vs SESUDAH proses
     -> kalau identik, data benar-benar utuh bit demi bit
     -> membandingkan hash jauh lebih meyakinkan daripada "dilihat
        sekilas kelihatannya sama", karena hash akan berubah drastis
        walau cuma 1 byte saja yang beda
  4. Hasilnya dicatat ke tabel, lalu diekspor ke Excel (.xlsx) sesuai
     syarat luaran tugas ("Data pengujian ... dalam format excel XLSX")

Cara menjalankan (dari folder root proyek):
    python pengujian/uji_kebenaran.py

Sebelum dijalankan: taruh file-file uji Anda (gambar, PDF, dsb) di
folder data_uji/. Kalau folder itu belum punya cukup 10 file, script
ini OTOMATIS membuatkan beberapa file teks & biner tambahan supaya
tetap ada minimal 10 kasus uji -- tapi untuk laporan yang meyakinkan,
sebaiknya Anda tambahkan sendiri file gambar (.jpg/.png) dan PDF asli
ke folder data_uji/ sebelum menjalankan script ini.
"""

import os
import sys
import hashlib
import string
import random

import pandas as pd

# Supaya bisa import modul dari folder src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from crypto_core import encrypt, decrypt, DekripsiGagalError

# ---------------------------------------------------------------------
# Konfigurasi
# ---------------------------------------------------------------------
FOLDER_DATA_UJI = os.path.join(os.path.dirname(__file__), "..", "data_uji")
FOLDER_HASIL = os.path.join(os.path.dirname(__file__), "hasil")
PASSWORD_UJI = "passwordUjiCoba!2024"
MINIMAL_KASUS_UJI = 10


def hitung_hash(data: bytes) -> str:
    """Menghitung hash SHA-256 dari data, dipakai untuk memastikan
    data sebelum dan sesudah proses benar-benar identik."""
    return hashlib.sha256(data).hexdigest()


def siapkan_data_teks_bervariasi() -> dict:
    """
    Menyiapkan beberapa kasus uji berupa TEKS dengan karakteristik
    berbeda-beda (bukan berkas fisik, langsung berupa bytes di memori).
    Ini melengkapi berkas fisik yang diambil dari folder data_uji/.
    """
    kasus = {}

    kasus["teks_pendek"] = "Halo dunia".encode("utf-8")

    kasus["teks_kosong"] = "".encode("utf-8")

    kasus["teks_panjang"] = (
        "Kriptografi adalah ilmu dan seni menjaga keamanan pesan. " * 50
    ).encode("utf-8")

    kasus["teks_karakter_unik"] = (
        "Simbol & angka: @#$%^&*() 123456 àéîõü 你好 😀🔒"
    ).encode("utf-8")

    # Teks acak besar (~50 KB) untuk variasi ukuran
    teks_acak = "".join(
        random.choices(string.ascii_letters + string.digits + " \n", k=50_000)
    )
    kasus["teks_acak_50kb"] = teks_acak.encode("utf-8")

    return kasus


def kumpulkan_berkas_dari_folder(folder: str) -> dict:
    """
    Membaca semua berkas yang ada di folder data_uji/, apa pun jenisnya
    (gambar, PDF, dokumen, dll), lalu mengembalikannya sebagai dict
    {nama_file: isi_bytes}.
    """
    kasus = {}
    if not os.path.isdir(folder):
        return kasus

    for nama_file in sorted(os.listdir(folder)):
        path_lengkap = os.path.join(folder, nama_file)
        if os.path.isfile(path_lengkap):
            with open(path_lengkap, "rb") as f:
                kasus[f"berkas_{nama_file}"] = f.read()

    return kasus


def buat_berkas_pelengkap_jika_kurang(folder: str, jumlah_sekarang: int,
                                        target: int) -> None:
    """
    Kalau berkas di data_uji/ belum mencapai target minimal, buatkan
    beberapa berkas tambahan otomatis (teks & biner acak) supaya
    jumlah kasus uji tetap terpenuhi >= 10.

    CATATAN PENTING: berkas otomatis ini hanya untuk MEMENUHI JUMLAH
    minimal. Untuk laporan yang meyakinkan dosen, tetap disarankan
    menambahkan berkas GAMBAR (.jpg/.png) dan PDF ASLI secara manual
    ke folder data_uji/, karena syarat tugas eksplisit menyebutkan
    "termasuk berkas gambar dan PDF".
    """
    os.makedirs(folder, exist_ok=True)
    kekurangan = target - jumlah_sekarang

    if kekurangan <= 0:
        return

    print(f"[INFO] Berkas di data_uji/ baru {jumlah_sekarang}, "
          f"membuat {kekurangan} berkas tambahan otomatis...")

    for i in range(kekurangan):
        nama = os.path.join(folder, f"auto_tambahan_{i+1}.bin")
        # Berkas biner acak ukuran bervariasi (1 KB sampai 20 KB)
        ukuran = random.randint(1_000, 20_000)
        with open(nama, "wb") as f:
            f.write(os.urandom(ukuran))


def jalankan_pengujian() -> pd.DataFrame:
    """
    Fungsi utama: menjalankan seluruh kasus uji, mengembalikan hasil
    sebagai DataFrame pandas (tabel) siap diekspor.
    """
    # 1. Kumpulkan kasus uji dari teks bervariasi
    semua_kasus = siapkan_data_teks_bervariasi()

    # 2. Tambahkan kasus uji dari berkas fisik di folder data_uji/
    berkas_ada = kumpulkan_berkas_dari_folder(FOLDER_DATA_UJI)
    semua_kasus.update(berkas_ada)

    # 3. Kalau jumlah masih kurang dari target, lengkapi otomatis
    if len(semua_kasus) < MINIMAL_KASUS_UJI:
        buat_berkas_pelengkap_jika_kurang(
            FOLDER_DATA_UJI, len(semua_kasus), MINIMAL_KASUS_UJI
        )
        # Kumpulkan ulang setelah ada tambahan
        berkas_ada = kumpulkan_berkas_dari_folder(FOLDER_DATA_UJI)
        semua_kasus.update(berkas_ada)

    print(f"\nTotal kasus uji yang akan dijalankan: {len(semua_kasus)}\n")

    # 4. Jalankan enkripsi -> dekripsi -> bandingkan hash, untuk tiap kasus
    baris_hasil = []
    for nomor, (nama_kasus, data_asli) in enumerate(semua_kasus.items(), start=1):
        hash_sebelum = hitung_hash(data_asli)

        try:
            paket_terenkripsi = encrypt(data_asli, PASSWORD_UJI)
            data_hasil_dekripsi = decrypt(paket_terenkripsi, PASSWORD_UJI)
            hash_sesudah = hitung_hash(data_hasil_dekripsi)
            status = "COCOK" if hash_sebelum == hash_sesudah else "TIDAK COCOK"
        except DekripsiGagalError as e:
            hash_sesudah = "-"
            status = f"ERROR: {e}"

        baris_hasil.append({
            "No": nomor,
            "Nama Kasus Uji": nama_kasus,
            "Ukuran (byte)": len(data_asli),
            "Hash Sebelum (SHA-256)": hash_sebelum[:16] + "...",
            "Hash Sesudah (SHA-256)": (
                hash_sesudah[:16] + "..." if hash_sesudah != "-" else "-"
            ),
            "Status": status,
        })

        tanda = "OK" if status == "COCOK" else "GAGAL"
        print(f"[{tanda}] Kasus {nomor}: {nama_kasus} "
              f"({len(data_asli)} byte) -> {status}")

    return pd.DataFrame(baris_hasil)


def main():
    df_hasil = jalankan_pengujian()

    print("\n" + "=" * 70)
    print("RINGKASAN")
    print("=" * 70)
    total = len(df_hasil)
    cocok = (df_hasil["Status"] == "COCOK").sum()
    print(f"Total kasus uji : {total}")
    print(f"Berhasil (COCOK): {cocok}")
    print(f"Gagal           : {total - cocok}")

    if cocok == total:
        print("\nSEMUA KASUS UJI LULUS. Kebenaran dekripsi terverifikasi.")
    else:
        print("\nADA KASUS YANG GAGAL! Periksa baris dengan status "
              "selain COCOK sebelum melanjutkan.")

    # Simpan hasil ke Excel, sesuai syarat luaran tugas
    os.makedirs(FOLDER_HASIL, exist_ok=True)
    path_excel = os.path.join(FOLDER_HASIL, "uji_kebenaran_dekripsi.xlsx")
    df_hasil.to_excel(path_excel, index=False)
    print(f"\nTabel hasil disimpan ke: {path_excel}")
    print("(Tinggal lampirkan/salin tabel ini ke laporan teknis Anda)")


if __name__ == "__main__":
    main()