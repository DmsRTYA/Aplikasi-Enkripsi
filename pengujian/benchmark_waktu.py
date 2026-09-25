"""
pengujian/benchmark_waktu.py
=============================
PENGUJIAN WAJIB #3: Waktu enkripsi dan dekripsi untuk berkas 1 KB,
1 MB, dan 10 MB.

Konsep
------
Test ini mengukur PERFORMA aplikasi -- apakah waktu prosesnya wajar
dan skalanya proporsional terhadap ukuran data. Untuk algoritma modern
seperti AES-GCM dan ChaCha20-Poly1305, waktu proses seharusnya naik
kurang lebih LINEAR terhadap ukuran data (2x data => kurang lebih 2x
waktu), karena keduanya adalah stream/block cipher yang memproses data
per-blok secara berurutan tanpa "ongkos" tambahan yang meledak seiring
ukuran data.

Setiap ukuran diuji BERULANG KALI (bukan cuma sekali), lalu diambil
rata-ratanya. Ini penting karena satu kali pengukuran bisa terganggu
oleh proses lain di sistem operasi (garbage collector, background
process, dsb) sehingga hasilnya tidak representatif kalau cuma diukur
1 kali.

Cara menjalankan (dari folder root proyek):
    python pengujian/benchmark_waktu.py
"""

import os
import sys
import time

import pandas as pd
import matplotlib
matplotlib.use("Agg")  # supaya bisa jalan tanpa tampilan GUI (headless)
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from crypto_core import encrypt, decrypt, METODE_AES_GCM
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kdf import generate_salt, derive_key

# ---------------------------------------------------------------------
# CATATAN PENTING TENTANG DESAIN PENGUJIAN INI
# ---------------------------------------------------------------------
# Fungsi encrypt() di crypto_core.py SELALU menjalankan derive_key()
# (PBKDF2, ratusan ribu iterasi) setiap kali dipanggil. Proses KDF ini
# makan waktu TETAP (tidak bergantung ukuran data), sehingga untuk
# data yang tidak terlalu besar (1 KB s.d. 10 MB), waktu KDF akan
# MENDOMINASI total waktu dan MENUTUPI kecepatan asli algoritma AES.
#
# Supaya benchmark ini benar-benar informatif dan menunjukkan
# skalabilitas AES yang sesungguhnya, kita ukur DUA hal terpisah:
#   1. Waktu KDF (diukur sekali saja -- tidak bergantung ukuran data)
#   2. Waktu AES murni per ukuran data (inilah yang menunjukkan
#      skalabilitas linear terhadap ukuran data)
# Kedua angka ini lalu dijumlahkan untuk mendapat "waktu total end-to-
# end" yang mencerminkan pengalaman pengguna sesungguhnya.
# ---------------------------------------------------------------------

# ---------------------------------------------------------------------
# Konfigurasi
# ---------------------------------------------------------------------
FOLDER_HASIL = os.path.join(os.path.dirname(__file__), "hasil")
PASSWORD_UJI = "passwordUjiCoba!2024"
JUMLAH_PENGULANGAN = 10  # tiap ukuran diuji 10x, lalu dirata-ratakan

UKURAN_UJI = {
    "1 KB": 1 * 1024,
    "1 MB": 1 * 1024 * 1024,
    "10 MB": 10 * 1024 * 1024,
}


def buat_data_acak(ukuran_byte: int) -> bytes:
    """Membuat data biner acak sepanjang ukuran_byte, sebagai simulasi
    berkas yang akan dienkripsi. Data ACAK dipakai (bukan data
    berulang) supaya representatif seperti berkas nyata (foto, PDF,
    dsb yang isinya tidak berpola)."""
    return os.urandom(ukuran_byte)


def ukur_waktu_kdf(pengulangan: int = JUMLAH_PENGULANGAN) -> float:
    """
    Mengukur waktu rata-rata proses KDF (turunkan kunci dari password)
    SEKALI SAJA, karena waktu ini tidak bergantung ukuran data yang
    mau dienkripsi -- KDF hanya memproses password, bukan data.
    """
    waktu_list = []
    for _ in range(pengulangan):
        salt = generate_salt()
        mulai = time.perf_counter()
        derive_key(PASSWORD_UJI, salt, metode="pbkdf2")
        selesai = time.perf_counter()
        waktu_list.append(selesai - mulai)
    return sum(waktu_list) / len(waktu_list)


def ukur_waktu_aes_murni(data: bytes, kunci: bytes,
                          pengulangan: int = JUMLAH_PENGULANGAN):
    """
    Mengukur waktu enkripsi/dekripsi AES MURNI (tanpa proses KDF),
    dengan kunci yang sudah siap pakai. Inilah yang benar-benar
    menunjukkan skalabilitas algoritma AES terhadap ukuran data.
    """
    waktu_enkripsi_list = []
    waktu_dekripsi_list = []
    aesgcm = AESGCM(kunci)

    for _ in range(pengulangan):
        nonce = os.urandom(12)

        mulai = time.perf_counter()
        cipherteks = aesgcm.encrypt(nonce, data, None)
        selesai = time.perf_counter()
        waktu_enkripsi_list.append(selesai - mulai)

        mulai = time.perf_counter()
        aesgcm.decrypt(nonce, cipherteks, None)
        selesai = time.perf_counter()
        waktu_dekripsi_list.append(selesai - mulai)

    rata2_enkripsi = sum(waktu_enkripsi_list) / len(waktu_enkripsi_list)
    rata2_dekripsi = sum(waktu_dekripsi_list) / len(waktu_dekripsi_list)

    return rata2_enkripsi, rata2_dekripsi


def jalankan_benchmark() -> tuple:
    """Menjalankan benchmark untuk semua ukuran yang dikonfigurasi.

    Returns
    -------
    (waktu_kdf, df_hasil) -- waktu_kdf dalam detik, df_hasil DataFrame
    """
    print("Mengukur waktu KDF (turunkan kunci dari password)...")
    waktu_kdf = ukur_waktu_kdf()
    print(f"  -> Waktu KDF rata-rata: {waktu_kdf*1000:.3f} ms "
          f"(konstan, tidak bergantung ukuran data)\n")

    # Kunci hanya perlu diturunkan sekali untuk benchmark AES murni,
    # karena yang mau diukur adalah kecepatan AES-nya, bukan KDF-nya
    salt = generate_salt()
    kunci = derive_key(PASSWORD_UJI, salt, metode="pbkdf2")

    baris_hasil = []

    for nama_ukuran, ukuran_byte in UKURAN_UJI.items():
        print(f"Menguji ukuran {nama_ukuran} "
              f"({ukuran_byte:,} byte), diulang {JUMLAH_PENGULANGAN}x...")

        data = buat_data_acak(ukuran_byte)
        rata2_enkripsi, rata2_dekripsi = ukur_waktu_aes_murni(data, kunci)

        baris_hasil.append({
            "Ukuran": nama_ukuran,
            "Ukuran (byte)": ukuran_byte,
            "Waktu AES Murni - Enkripsi (detik)": round(rata2_enkripsi, 6),
            "Waktu AES Murni - Dekripsi (detik)": round(rata2_dekripsi, 6),
            "Waktu Total (KDF + AES) - Enkripsi (detik)": round(
                waktu_kdf + rata2_enkripsi, 6
            ),
            "Kecepatan AES Murni (MB/detik)": round(
                (ukuran_byte / 1_048_576) / rata2_enkripsi, 2
            ) if rata2_enkripsi > 0 else float("inf"),
        })

        print(f"  -> AES murni  : enkripsi {rata2_enkripsi*1000:.4f} ms | "
              f"dekripsi {rata2_dekripsi*1000:.4f} ms")
        print(f"  -> Total (KDF+AES): {(waktu_kdf + rata2_enkripsi)*1000:.3f} ms")

    return waktu_kdf, pd.DataFrame(baris_hasil)


def pengulangan_info(ukuran_byte: int) -> str:
    """Info tambahan biar output terminal lebih informatif."""
    return f"{ukuran_byte:,} byte"


def buat_grafik(df: pd.DataFrame, path_output: str) -> None:
    """Membuat grafik batang perbandingan waktu AES murni (enkripsi vs
    dekripsi) untuk tiap ukuran, disimpan sebagai PNG siap tempel di
    laporan. Sengaja pakai skala waktu AES MURNI (tanpa KDF) supaya
    kenaikan linear terhadap ukuran data terlihat jelas -- kalau
    dicampur dengan waktu KDF yang konstan, kenaikannya akan
    tersamarkan (lihat catatan di kepala file)."""
    fig, ax = plt.subplots(figsize=(8, 5))

    x = range(len(df))
    lebar = 0.35

    ax.bar(
        [i - lebar / 2 for i in x],
        df["Waktu AES Murni - Enkripsi (detik)"] * 1000,  # ke milidetik
        width=lebar,
        label="Enkripsi (AES murni)",
        color="#2d6a4f",
    )
    ax.bar(
        [i + lebar / 2 for i in x],
        df["Waktu AES Murni - Dekripsi (detik)"] * 1000,
        width=lebar,
        label="Dekripsi (AES murni)",
        color="#f4a300",
    )

    ax.set_xticks(list(x))
    ax.set_xticklabels(df["Ukuran"])
    ax.set_ylabel("Waktu rata-rata (milidetik)")
    ax.set_title(
        f"Waktu AES-256-GCM Murni (tanpa KDF) vs Ukuran Data\n"
        f"(rata-rata dari {JUMLAH_PENGULANGAN} kali pengulangan)"
    )
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.4)

    plt.tight_layout()
    plt.savefig(path_output, dpi=150)
    plt.close()


def main():
    print("=" * 70)
    print("BENCHMARK WAKTU ENKRIPSI/DEKRIPSI (AES-256-GCM)")
    print("=" * 70)

    waktu_kdf, df_hasil = jalankan_benchmark()

    print("\n" + "=" * 70)
    print("TABEL HASIL")
    print("=" * 70)
    print(df_hasil.to_string(index=False))

    # Analisis singkat: cek apakah waktu AES MURNI naik proporsional
    print("\n" + "=" * 70)
    print("ANALISIS SKALABILITAS (berdasarkan waktu AES MURNI, tanpa KDF)")
    print("=" * 70)
    waktu_1kb = df_hasil.iloc[0]["Waktu AES Murni - Enkripsi (detik)"]
    waktu_1mb = df_hasil.iloc[1]["Waktu AES Murni - Enkripsi (detik)"]
    waktu_10mb = df_hasil.iloc[2]["Waktu AES Murni - Enkripsi (detik)"]

    if waktu_1kb > 0:
        rasio_1mb = waktu_1mb / waktu_1kb
        print(f"Rasio waktu 1MB / 1KB : {rasio_1mb:,.1f}x "
              f"(ukuran data naik {1024}x)")
    if waktu_1mb > 0:
        rasio_10mb = waktu_10mb / waktu_1mb
        print(f"Rasio waktu 10MB / 1MB: {rasio_10mb:,.1f}x "
              f"(ukuran data naik 10x)")
        if 7 <= rasio_10mb <= 13:
            print("-> Kenaikan waktu PROPORSIONAL/LINEAR terhadap ukuran "
                  "data. Ini bagus, sesuai karakteristik AES-GCM yang "
                  "efisien untuk data besar.")
        else:
            print("-> Kenaikan waktu belum sepenuhnya linear pada skala "
                  "ini. Wajar terjadi sedikit variasi karena overhead "
                  "sistem, apalagi untuk data yang relatif kecil.")

    print(f"\nCatatan: waktu KDF (turunkan kunci dari password) berkisar "
          f"{waktu_kdf*1000:.1f} ms dan KONSTAN, tidak bergantung ukuran "
          f"data. Untuk berkas kecil, waktu KDF ini justru mendominasi "
          f"waktu total dibanding proses AES itu sendiri -- ini alasan "
          f"kenapa analisis skalabilitas di atas dihitung dari waktu AES "
          f"murni, bukan waktu total.")

    # Simpan tabel ke Excel (termasuk baris info waktu KDF)
    os.makedirs(FOLDER_HASIL, exist_ok=True)
    path_excel = os.path.join(FOLDER_HASIL, "benchmark_waktu.xlsx")

    df_untuk_excel = df_hasil.copy()
    with pd.ExcelWriter(path_excel) as writer:
        df_untuk_excel.to_excel(writer, index=False, sheet_name="Benchmark")
        pd.DataFrame([{
            "Keterangan": "Waktu KDF rata-rata (konstan)",
            "Nilai (detik)": round(waktu_kdf, 6),
            "Nilai (ms)": round(waktu_kdf * 1000, 3),
        }]).to_excel(writer, index=False, sheet_name="Info KDF")

    print(f"\nTabel hasil disimpan ke: {path_excel}")

    # Simpan grafik
    path_grafik = os.path.join(FOLDER_HASIL, "grafik_waktu_proses.png")
    buat_grafik(df_hasil, path_grafik)
    print(f"Grafik disimpan ke     : {path_grafik}")
    print("\n(Tabel dan grafik ini siap ditempel langsung ke laporan teknis)")


if __name__ == "__main__":
    main()