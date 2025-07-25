import numpy as np
from PIL import Image
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
import os
from skimage.metrics import mean_squared_error, peak_signal_noise_ratio, structural_similarity

def calculate_correlation_coefficient(img1, img2):
    """Menghitung Correlation Coefficient (CC) antara dua gambar."""
    if img1.shape != img2.shape:
        raise ValueError("Ukuran gambar harus sama")
    img1_flat = img1.flatten()
    img2_flat = img2.flatten()
    # np.corrcoef mengembalikan matriks korelasi, ambil nilai di luar diagonal
    return np.corrcoef(img1_flat, img2_flat)[0, 1]

def calculate_npcr(img1, img2):
    """Menghitung Number of Pixels Change Rate (NPCR)."""
    if img1.shape != img2.shape:
        raise ValueError("Ukuran gambar harus sama")
    
    # Hitung jumlah piksel yang berbeda
    diff_pixels = np.sum(img1 != img2)
    total_pixels = img1.size
    
    # Kembalikan dalam persentase
    return (diff_pixels / total_pixels) * 100

def calculate_uaci(img1, img2):
    """Menghitung Unified Average Changing Intensity (UACI)."""
    if img1.shape != img2.shape:
        raise ValueError("Ukuran gambar harus sama")

    # Pastikan tipe data float untuk menghindari overflow
    img1_f = img1.astype(np.float64)
    img2_f = img2.astype(np.float64)

    # Hitung total selisih absolut dan normalisasi
    total_diff = np.sum(np.abs(img1_f - img2_f))
    total_pixels = img1.size
    max_intensity = 255 # Untuk gambar 8-bit

    # Kembalikan dalam persentase
    return (total_diff / (total_pixels * max_intensity)) * 100

def evaluate_metrics(img1, img2):
    """Menjalankan semua metrik evaluasi untuk dua gambar."""
    # Pastikan gambar dalam format yang tepat (8-bit grayscale)
    if img1.dtype != np.uint8: img1 = img1.astype(np.uint8)
    if img2.dtype != np.uint8: img2 = img2.astype(np.uint8)

    # Scikit-image metrics
    mse = mean_squared_error(img1, img2)
    psnr = peak_signal_noise_ratio(img1, img2, data_range=255)
    ssim = structural_similarity(img1, img2, data_range=255)

    # Custom metrics
    cc = calculate_correlation_coefficient(img1, img2)
    npcr = calculate_npcr(img1, img2)
    uaci = calculate_uaci(img1, img2)

    return {
        "MSE": mse,
        "PSNR": psnr,
        "SSIM": ssim,
        "Correlation Coefficient (CC)": cc,
        "NPCR (%)": npcr,
        "UACI (%)": uaci
    }

def encrypt_decrypt_evaluate(image_path):
    """
    Fungsi utama untuk memuat gambar, mengenkripsi, mendekripsi,
    dan mengevaluasi hasilnya.
    """
    # 1. Muat dan siapkan gambar
    try:
        # Konversi ke 'L' untuk grayscale agar perhitungan lebih sederhana & umum
        original_image_pil = Image.open(image_path).convert('L') 
        original_array = np.array(original_image_pil)
        print(f"Gambar '{image_path}' berhasil dimuat. Ukuran: {original_array.shape}")
    except FileNotFoundError:
        print(f"Error: File '{image_path}' tidak ditemukan.")
        return

    # 2. Siapkan parameter ChaCha20
    key = get_random_bytes(32)  # Kunci 256-bit (32 byte)
    nonce = get_random_bytes(12) # Nonce 96-bit (12 byte), umum untuk ChaCha20

    # 3. Enkripsi
    image_bytes = original_array.tobytes()
    cipher = ChaCha20.new(key=key, nonce=nonce)
    encrypted_bytes = cipher.encrypt(image_bytes)
    encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8).reshape(original_array.shape)

    # 4. Dekripsi
    # Penting: Buat ulang cipher object dengan key dan nonce yang sama
    decipher = ChaCha20.new(key=key, nonce=nonce)
    decrypted_bytes = decipher.decrypt(encrypted_bytes)
    decrypted_array = np.frombuffer(decrypted_bytes, dtype=np.uint8).reshape(original_array.shape)

    # 5. Simpan gambar hasil
    encrypted_image_pil = Image.fromarray(encrypted_array)
    decrypted_image_pil = Image.fromarray(decrypted_array)
    
    base_name = os.path.splitext(image_path)[0]
    encrypted_path = f"{base_name}_encrypted.png"
    decrypted_path = f"{base_name}_decrypted.png"

    encrypted_image_pil.save(encrypted_path)
    decrypted_image_pil.save(decrypted_path)
    print(f"Gambar terenkripsi disimpan di: {encrypted_path}")
    print(f"Gambar terdekripsi disimpan di: {decrypted_path}")

    # 6. Lakukan evaluasi untuk setiap perbandingan
    print("\n" + "="*50)
    print("|| HASIL EVALUASI METRIK ||")
    print("="*50)

    # Perbandingan 1: Original vs Decrypted
    print("\n--- 1. Original vs. Decrypted ---")
    print("(Harapannya: Tidak ada error, similaritas sempurna)")
    metrics_orig_dec = evaluate_metrics(original_array, decrypted_array)
    for key_metric, value in metrics_orig_dec.items():
        print(f"{key_metric:<28}: {value}")

    # Perbandingan 2: Original vs Encrypted
    print("\n--- 2. Original vs. Encrypted ---")
    print("(Harapannya: Error tinggi, similaritas sangat rendah)")
    metrics_orig_enc = evaluate_metrics(original_array, encrypted_array)
    for key_metric, value in metrics_orig_enc.items():
        print(f"{key_metric:<28}: {value}")

    # Perbandingan 3: Encrypted vs Decrypted
    print("\n--- 3. Encrypted vs. Decrypted ---")
    print("(Harapannya: Error tinggi, similaritas sangat rendah)")
    metrics_enc_dec = evaluate_metrics(encrypted_array, decrypted_array)
    for key_metric, value in metrics_enc_dec.items():
        print(f"{key_metric:<28}: {value}")
    
    print("\n" + "="*50)


if __name__ == '__main__':
    # Ganti "sample_image.png" dengan path gambar Anda
    input_image_file = "sample.jpeg"

    # Membuat gambar contoh jika tidak ada
    if not os.path.exists(input_image_file):
        print(f"File '{input_image_file}' tidak ditemukan. Membuat gambar contoh...")
        sample_array = np.zeros((256, 256), dtype=np.uint8)
        x, y = np.meshgrid(np.arange(256), np.arange(256))
        sample_array = ((x + y) / 2).astype(np.uint8) # Gradien diagonal
        Image.fromarray(sample_array).save(input_image_file)
        print("Gambar contoh 'sample_image.png' telah dibuat.")

    encrypt_decrypt_evaluate(input_image_file)