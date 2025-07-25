import numpy as np
from PIL import Image
from Crypto.Cipher import ChaCha20, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime
import matplotlib.pyplot as plt
from skimage.metrics import mean_squared_error, peak_signal_noise_ratio, structural_similarity

def select_image_file():
    """Membuka dialog untuk memilih file gambar."""
    root = tk.Tk()
    root.withdraw()  # Sembunyikan window utama
    
    file_types = [
        ('Image files', '*.png *.jpg *.jpeg *.bmp *.tiff *.gif'),
        ('PNG files', '*.png'),
        ('JPEG files', '*.jpg *.jpeg'),
        ('All files', '*.*')
    ]
    
    file_path = filedialog.askopenfilename(
        title="Pilih file gambar untuk dienkripsi",
        filetypes=file_types
    )
    
    root.destroy()
    return file_path

def save_metrics_to_file(metrics_data, image_path):
    """Menyimpan hasil metrik evaluasi ke file teks."""
    # Buat nama file hasil berdasarkan nama gambar input
    base_name = os.path.splitext(os.path.basename(image_path))[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{base_name}_comparison_metrics_{timestamp}.txt"
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("="*70 + "\n")
            f.write("HASIL EVALUASI METRIK PERBANDINGAN AES-CBC vs ChaCha20\n")
            f.write("="*70 + "\n")
            f.write(f"File Gambar: {os.path.basename(image_path)}\n")
            f.write(f"Waktu Evaluasi: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*70 + "\n\n")
            
            for comparison_name, metrics in metrics_data.items():
                f.write(f"--- {comparison_name} ---\n")
                for metric_name, value in metrics.items():
                    if isinstance(value, float):
                        if value == float('inf'):
                            f.write(f"{metric_name:<28}: ∞ (Perfect match)\n")
                        else:
                            f.write(f"{metric_name:<28}: {value:.6f}\n")
                    else:
                        f.write(f"{metric_name:<28}: {value}\n")
                f.write("\n")
            
            f.write("="*70 + "\n")
            f.write("Keterangan:\n")
            f.write("- MSE: Mean Squared Error (semakin kecil semakin baik)\n")
            f.write("- PSNR: Peak Signal-to-Noise Ratio (semakin besar semakin baik)\n")
            f.write("- SSIM: Structural Similarity Index (0-1, semakin besar semakin baik)\n")
            f.write("- CC: Correlation Coefficient (-1 hingga 1, mendekati 0 untuk enkripsi yang baik)\n")
            f.write("- NPCR: Number of Pixels Change Rate (%, semakin besar semakin baik untuk enkripsi)\n")
            f.write("- UACI: Unified Average Changing Intensity (%, optimal sekitar 33.46%)\n\n")
            f.write("Analisis Perbandingan:\n")
            f.write("- Algoritma dengan NPCR dan UACI lebih tinggi = enkripsi lebih kuat\n")
            f.write("- Algoritma dengan CC lebih mendekati 0 = enkripsi lebih acak\n")
            f.write("- Original vs Decrypted harus identik untuk validasi algoritma\n")
        
        print(f"Hasil metrik perbandingan disimpan ke: {output_file}")
        return output_file
    except Exception as e:
        print(f"Error saat menyimpan file metrik: {e}")
        return None

def display_images(original_array, aes_encrypted_array, chacha_encrypted_array, 
                  aes_decrypted_array, chacha_decrypted_array, image_path):
    """Menampilkan 5 gambar: original, AES encrypted, ChaCha20 encrypted, AES decrypted, ChaCha20 decrypted."""
    try:
        # Konfigurasi matplotlib untuk tampilan yang lebih baik
        plt.style.use('default')
        fig, axes = plt.subplots(1, 5, figsize=(20, 4))
        fig.suptitle(f'Perbandingan AES-CBC vs ChaCha20 - {os.path.basename(image_path)}', 
                    fontsize=16, fontweight='bold')
        
        # Gambar Original
        axes[0].imshow(original_array, cmap='gray', vmin=0, vmax=255)
        axes[0].set_title('Original Image', fontweight='bold')
        axes[0].axis('off')
        axes[0].text(0.02, 0.98, f'Size:\n{original_array.shape}', 
                    transform=axes[0].transAxes, verticalalignment='top',
                    bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))
        
        # Gambar AES Encrypted
        axes[1].imshow(aes_encrypted_array, cmap='gray', vmin=0, vmax=255)
        axes[1].set_title('AES-CBC Encrypted', fontweight='bold', color='red')
        axes[1].axis('off')
        axes[1].text(0.02, 0.98, 'AES-CBC\nEncrypted', 
                    transform=axes[1].transAxes, verticalalignment='top', color='white',
                    bbox=dict(boxstyle='round', facecolor='red', alpha=0.7))
        
        # Gambar ChaCha20 Encrypted
        axes[2].imshow(chacha_encrypted_array, cmap='gray', vmin=0, vmax=255)
        axes[2].set_title('ChaCha20 Encrypted', fontweight='bold', color='darkred')
        axes[2].axis('off')
        axes[2].text(0.02, 0.98, 'ChaCha20\nEncrypted', 
                    transform=axes[2].transAxes, verticalalignment='top', color='white',
                    bbox=dict(boxstyle='round', facecolor='darkred', alpha=0.7))
        
        # Gambar AES Decrypted
        axes[3].imshow(aes_decrypted_array, cmap='gray', vmin=0, vmax=255)
        axes[3].set_title('AES-CBC Decrypted', fontweight='bold', color='green')
        axes[3].axis('off')
        axes[3].text(0.02, 0.98, 'AES-CBC\nDecrypted', 
                    transform=axes[3].transAxes, verticalalignment='top', color='white',
                    bbox=dict(boxstyle='round', facecolor='green', alpha=0.7))
        
        # Gambar ChaCha20 Decrypted
        axes[4].imshow(chacha_decrypted_array, cmap='gray', vmin=0, vmax=255)
        axes[4].set_title('ChaCha20 Decrypted', fontweight='bold', color='darkgreen')
        axes[4].axis('off')
        axes[4].text(0.02, 0.98, 'ChaCha20\nDecrypted', 
                    transform=axes[4].transAxes, verticalalignment='top', color='white',
                    bbox=dict(boxstyle='round', facecolor='darkgreen', alpha=0.7))
        
        # Tambahkan informasi di bawah
        info_text = (
            "ANALISIS VISUAL PERBANDINGAN:\n"
            "• Original vs Decrypted (AES & ChaCha20): Harus identik (validasi algoritma)\n"
            "• Encrypted images: Kedua algoritma harus menghasilkan noise yang berbeda\n"
            "TIP: Klik gambar untuk zoom. Tutup window ini untuk melanjutkan program."
        )
        fig.text(0.5, 0.02, info_text, ha='center', va='bottom', fontsize=10,
                bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8, pad=0.5))
        
        # Atur layout agar rapi
        plt.tight_layout()
        plt.subplots_adjust(top=0.85, bottom=0.15)
        
        # Tampilkan window
        plt.show()
        
        print("Tampilan gambar ditutup. Melanjutkan program...")
        
    except Exception as e:
        print(f"Error saat menampilkan gambar: {e}")
        print("Program tetap melanjutkan tanpa tampilan gambar.")

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
    
    # Handle PSNR calculation untuk menghindari divide by zero
    if mse == 0:
        psnr = float('inf')  # PSNR tak terhingga jika gambar identik
    else:
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

def encrypt_decrypt_compare(image_path):
    """
    Fungsi utama untuk memuat gambar, mengenkripsi dengan AES-CBC dan ChaCha20,
    mendekripsi, dan mengevaluasi perbandingan hasilnya.
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

    # 2. Siapkan parameter untuk kedua algoritma
    # AES-CBC parameters
    aes_key = get_random_bytes(32)  # Kunci 256-bit untuk AES-256
    aes_iv = get_random_bytes(16)   # IV 128-bit untuk AES

    # ChaCha20 parameters
    chacha_key = get_random_bytes(32)  # Kunci 256-bit
    chacha_nonce = get_random_bytes(12) # Nonce 96-bit

    # 3. Enkripsi dengan AES-CBC
    print("\n--- Enkripsi dengan AES-CBC ---")
    image_bytes = original_array.tobytes()
    
    # Padding untuk AES (blok 16 byte)
    padded_data = pad(image_bytes, AES.block_size)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    aes_encrypted_bytes = aes_cipher.encrypt(padded_data)
    
    # Reshape untuk AES (ukuran bisa berubah karena padding)
    aes_encrypted_flat = np.frombuffer(aes_encrypted_bytes, dtype=np.uint8)
    # Potong ke ukuran asli untuk visualisasi
    aes_encrypted_visual = aes_encrypted_flat[:original_array.size]
    aes_encrypted_array = aes_encrypted_visual.reshape(original_array.shape)
    print(f"AES-CBC enkripsi selesai. Ukuran data: {len(aes_encrypted_bytes)} bytes")

    # 4. Enkripsi dengan ChaCha20
    print("--- Enkripsi dengan ChaCha20 ---")
    chacha_cipher = ChaCha20.new(key=chacha_key, nonce=chacha_nonce)
    chacha_encrypted_bytes = chacha_cipher.encrypt(image_bytes)
    chacha_encrypted_array = np.frombuffer(chacha_encrypted_bytes, dtype=np.uint8).reshape(original_array.shape)
    print(f"ChaCha20 enkripsi selesai. Ukuran data: {len(chacha_encrypted_bytes)} bytes")

    # 5. Dekripsi AES-CBC
    print("--- Dekripsi dengan AES-CBC ---")
    aes_decipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    aes_decrypted_padded = aes_decipher.decrypt(aes_encrypted_bytes)
    aes_decrypted_bytes = unpad(aes_decrypted_padded, AES.block_size)
    aes_decrypted_array = np.frombuffer(aes_decrypted_bytes, dtype=np.uint8).reshape(original_array.shape)
    print("AES-CBC dekripsi selesai.")

    # 6. Dekripsi ChaCha20
    print("--- Dekripsi dengan ChaCha20 ---")
    chacha_decipher = ChaCha20.new(key=chacha_key, nonce=chacha_nonce)
    chacha_decrypted_bytes = chacha_decipher.decrypt(chacha_encrypted_bytes)
    chacha_decrypted_array = np.frombuffer(chacha_decrypted_bytes, dtype=np.uint8).reshape(original_array.shape)
    print("ChaCha20 dekripsi selesai.")

    # 7. Simpan semua gambar hasil
    base_name = os.path.splitext(image_path)[0]
    
    aes_encrypted_path = f"{base_name}_AES_encrypted.png"
    chacha_encrypted_path = f"{base_name}_ChaCha20_encrypted.png"
    aes_decrypted_path = f"{base_name}_AES_decrypted.png"
    chacha_decrypted_path = f"{base_name}_ChaCha20_decrypted.png"

    Image.fromarray(aes_encrypted_array).save(aes_encrypted_path)
    Image.fromarray(chacha_encrypted_array).save(chacha_encrypted_path)
    Image.fromarray(aes_decrypted_array).save(aes_decrypted_path)
    Image.fromarray(chacha_decrypted_array).save(chacha_decrypted_path)
    
    print(f"\nGambar hasil disimpan:")
    print(f"  AES encrypted: {aes_encrypted_path}")
    print(f"  ChaCha20 encrypted: {chacha_encrypted_path}")
    print(f"  AES decrypted: {aes_decrypted_path}")
    print(f"  ChaCha20 decrypted: {chacha_decrypted_path}")

    # 8. Evaluasi metrik untuk semua perbandingan
    print("\n" + "="*60)
    print("|| HASIL EVALUASI METRIK PERBANDINGAN ||")
    print("="*60)

    all_metrics = {}

    # Validasi dekripsi AES
    print("\n--- VALIDASI AES-CBC ---")
    print("Original vs AES Decrypted (harus identik):")
    aes_validation = evaluate_metrics(original_array, aes_decrypted_array)
    all_metrics["AES-CBC Validation (Original vs Decrypted)"] = aes_validation
    for key_metric, value in aes_validation.items():
        if key_metric == "PSNR" and value == float('inf'):
            print(f"  {key_metric:<26}: ∞ (Perfect match)")
        else:
            print(f"  {key_metric:<26}: {value}")

    # Validasi dekripsi ChaCha20
    print("\n--- VALIDASI ChaCha20 ---")
    print("Original vs ChaCha20 Decrypted (harus identik):")
    chacha_validation = evaluate_metrics(original_array, chacha_decrypted_array)
    all_metrics["ChaCha20 Validation (Original vs Decrypted)"] = chacha_validation
    for key_metric, value in chacha_validation.items():
        if key_metric == "PSNR" and value == float('inf'):
            print(f"  {key_metric:<26}: ∞ (Perfect match)")
        else:
            print(f"  {key_metric:<26}: {value}")

    # Perbandingan enkripsi AES vs Original
    print("\n--- ANALISIS ENKRIPSI AES-CBC ---")
    print("Original vs AES Encrypted (harus sangat berbeda):")
    aes_encryption_analysis = evaluate_metrics(original_array, aes_encrypted_array)
    all_metrics["AES-CBC Encryption Analysis (Original vs Encrypted)"] = aes_encryption_analysis
    for key_metric, value in aes_encryption_analysis.items():
        print(f"  {key_metric:<26}: {value}")

    # Perbandingan enkripsi ChaCha20 vs Original
    print("\n--- ANALISIS ENKRIPSI ChaCha20 ---")
    print("Original vs ChaCha20 Encrypted (harus sangat berbeda):")
    chacha_encryption_analysis = evaluate_metrics(original_array, chacha_encrypted_array)
    all_metrics["ChaCha20 Encryption Analysis (Original vs Encrypted)"] = chacha_encryption_analysis
    for key_metric, value in chacha_encryption_analysis.items():
        print(f"  {key_metric:<26}: {value}")

    # Perbandingan langsung AES vs ChaCha20 (encrypted)
    print("\n--- PERBANDINGAN LANGSUNG ---")
    print("AES Encrypted vs ChaCha20 Encrypted (harus berbeda):")
    direct_comparison = evaluate_metrics(aes_encrypted_array, chacha_encrypted_array)
    all_metrics["Direct Comparison (AES Encrypted vs ChaCha20 Encrypted)"] = direct_comparison
    for key_metric, value in direct_comparison.items():
        print(f"  {key_metric:<26}: {value}")

    print("\n" + "="*60)
    
    # Simpan hasil metrik ke file
    save_metrics_to_file(all_metrics, image_path)
    
    # Tampilkan semua gambar dalam satu window
    print("\nMenampilkan perbandingan 5 gambar...")
    display_images(original_array, aes_encrypted_array, chacha_encrypted_array, 
                  aes_decrypted_array, chacha_decrypted_array, image_path)


if __name__ == '__main__':
    print("=== PROGRAM PERBANDINGAN ENKRIPSI AES-CBC vs ChaCha20 ===\n")
    
    # Pilih file gambar menggunakan dialog
    input_image_file = select_image_file()
    
    if not input_image_file:
        print("Tidak ada file yang dipilih. Program dihentikan.")
    else:
        print(f"File yang dipilih: {input_image_file}")
        
        # Pastikan file ada dan dapat dibaca
        if not os.path.exists(input_image_file):
            messagebox.showerror("Error", f"File '{input_image_file}' tidak ditemukan!")
        else:
            try:
                # Jalankan proses perbandingan enkripsi dan evaluasi
                encrypt_decrypt_compare(input_image_file)
                print("\nProses perbandingan selesai! Periksa folder untuk melihat:")
                print("- 5 gambar hasil (original, 2 encrypted, 2 decrypted)")
                print("- File metrik perbandingan dalam format .txt")
            except Exception as e:
                print(f"Error saat memproses gambar: {e}")
                messagebox.showerror("Error", f"Terjadi kesalahan: {str(e)}")