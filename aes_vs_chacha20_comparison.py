import numpy as np
from PIL import Image
from Crypto.Cipher import ChaCha20, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from datetime import datetime
import matplotlib.pyplot as plt
from skimage.metrics import mean_squared_error, peak_signal_noise_ratio, structural_similarity
import hashlib

def get_encryption_keys():
    """Membuat GUI untuk input kunci enkripsi."""
    root = tk.Tk()
    root.title("Input Kunci Enkripsi")
    root.geometry("550x500")
    root.resizable(True, True)  # Allow resizing
    root.minsize(500, 450)  # Set minimum size
    
    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (550 // 2)
    y = (root.winfo_screenheight() // 2) - (500 // 2)
    root.geometry(f"550x500+{x}+{y}")
    
    # Variables to store results
    result = {"cancelled": True}
    
    # Create main container with scrollbar
    main_container = ttk.Frame(root)
    main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
    # Create canvas and scrollbar for scrolling
    canvas = tk.Canvas(main_container)
    scrollbar = ttk.Scrollbar(main_container, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas)
    
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    
    # Pack canvas and scrollbar
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    # Main frame inside scrollable area
    main_frame = ttk.Frame(scrollable_frame, padding="20")
    main_frame.pack(fill=tk.BOTH, expand=True)
    
    # Title
    title_label = ttk.Label(main_frame, text="KONFIGURASI KUNCI ENKRIPSI", 
                           font=("Arial", 14, "bold"))
    title_label.pack(pady=(0, 20))
    
    # AES Key section
    aes_frame = ttk.LabelFrame(main_frame, text="AES-CBC Key (32 karakter untuk AES-256)", padding="15")
    aes_frame.pack(fill=tk.X, pady=(0, 15))
    
    ttk.Label(aes_frame, text="Masukkan kunci AES:").pack(anchor=tk.W, pady=(0, 5))
    aes_entry = ttk.Entry(aes_frame, width=60, show="*")
    aes_entry.pack(fill=tk.X, pady=(0, 5))
    
    aes_show_var = tk.BooleanVar()
    aes_show_check = ttk.Checkbutton(aes_frame, text="Tampilkan kunci", variable=aes_show_var,
                                    command=lambda: aes_entry.config(show="" if aes_show_var.get() else "*"))
    aes_show_check.pack(anchor=tk.W, pady=(0, 5))
    
    aes_random_btn = ttk.Button(aes_frame, text="Generate Random", 
                               command=lambda: aes_entry.delete(0, tk.END) or aes_entry.insert(0, os.urandom(32).hex()[:32]))
    aes_random_btn.pack(anchor=tk.W, pady=(0, 5))
    
    # ChaCha20 Key section
    chacha_frame = ttk.LabelFrame(main_frame, text="ChaCha20 Key (32 karakter)", padding="15")
    chacha_frame.pack(fill=tk.X, pady=(0, 15))
    
    ttk.Label(chacha_frame, text="Masukkan kunci ChaCha20:").pack(anchor=tk.W, pady=(0, 5))
    chacha_entry = ttk.Entry(chacha_frame, width=60, show="*")
    chacha_entry.pack(fill=tk.X, pady=(0, 5))
    
    chacha_show_var = tk.BooleanVar()
    chacha_show_check = ttk.Checkbutton(chacha_frame, text="Tampilkan kunci", variable=chacha_show_var,
                                       command=lambda: chacha_entry.config(show="" if chacha_show_var.get() else "*"))
    chacha_show_check.pack(anchor=tk.W, pady=(0, 5))
    
    chacha_random_btn = ttk.Button(chacha_frame, text="Generate Random", 
                                  command=lambda: chacha_entry.delete(0, tk.END) or chacha_entry.insert(0, os.urandom(32).hex()[:32]))
    chacha_random_btn.pack(anchor=tk.W, pady=(0, 5))
    
    # Options
    options_frame = ttk.LabelFrame(main_frame, text="Opsi", padding="15")
    options_frame.pack(fill=tk.X, pady=(0, 20))
    
    same_key_var = tk.BooleanVar()
    same_key_check = ttk.Checkbutton(options_frame, text="Gunakan kunci yang sama untuk kedua algoritma", 
                                    variable=same_key_var)
    same_key_check.pack(anchor=tk.W, pady=(0, 10))
    
    # Info text
    info_text = ttk.Label(options_frame, 
                         text="• Kunci minimal 16 karakter\n• Akan di-hash menggunakan SHA-256 menjadi 32 bytes\n• Generate Random akan membuat kunci acak 32 karakter",
                         foreground="gray")
    info_text.pack(anchor=tk.W)
    
    def validate_and_submit():
        aes_key_text = aes_entry.get().strip()
        chacha_key_text = chacha_entry.get().strip()
        
        # Use same key if checkbox is checked
        if same_key_var.get() and aes_key_text:
            chacha_key_text = aes_key_text
            chacha_entry.delete(0, tk.END)
            chacha_entry.insert(0, aes_key_text)
        elif same_key_var.get() and chacha_key_text:
            aes_key_text = chacha_key_text
            aes_entry.delete(0, tk.END)
            aes_entry.insert(0, chacha_key_text)
        
        # Validate keys
        if not aes_key_text or len(aes_key_text) < 16:
            messagebox.showerror("Error", "Kunci AES harus minimal 16 karakter!")
            return
        
        if not chacha_key_text or len(chacha_key_text) < 16:
            messagebox.showerror("Error", "Kunci ChaCha20 harus minimal 16 karakter!")
            return
        
        # Convert to proper key format
        try:
            # Pad or truncate to 32 bytes
            aes_key_bytes = hashlib.sha256(aes_key_text.encode()).digest()
            chacha_key_bytes = hashlib.sha256(chacha_key_text.encode()).digest()
            
            result.update({
                "cancelled": False,
                "aes_key": aes_key_bytes,
                "chacha_key": chacha_key_bytes,
                "aes_key_text": aes_key_text,
                "chacha_key_text": chacha_key_text
            })
            root.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Error dalam memproses kunci: {str(e)}")
    
    # Buttons frame - fixed at bottom
    button_frame = ttk.Frame(main_frame)
    button_frame.pack(fill=tk.X, pady=(20, 0))
    
    # Create button container for centering
    button_container = ttk.Frame(button_frame)
    button_container.pack()
    
    ttk.Button(button_container, text="Gunakan Kunci Random", 
              command=lambda: [aes_entry.delete(0, tk.END), chacha_entry.delete(0, tk.END),
                              aes_entry.insert(0, os.urandom(16).hex()), 
                              chacha_entry.insert(0, os.urandom(16).hex()),
                              validate_and_submit()]).pack(side=tk.LEFT, padx=(0, 10))
    
    ttk.Button(button_container, text="OK", command=validate_and_submit).pack(side=tk.LEFT, padx=(0, 10))
    ttk.Button(button_container, text="Cancel", command=root.destroy).pack(side=tk.LEFT)
    
    # Bind mouse wheel to canvas
    def _on_mousewheel(event):
        canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def bind_to_mousewheel(event):
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
    
    def unbind_from_mousewheel(event):
        canvas.unbind_all("<MouseWheel>")
    
    canvas.bind('<Enter>', bind_to_mousewheel)
    canvas.bind('<Leave>', unbind_from_mousewheel)
    
    # Update scroll region after everything is packed
    root.update_idletasks()
    canvas.configure(scrollregion=canvas.bbox("all"))
    
    root.mainloop()
    return result

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

def save_metrics_to_file(metrics_data, image_path, aes_key_text=None, chacha_key_text=None):
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
            
            # Tambahkan informasi kunci jika tersedia
            if aes_key_text and chacha_key_text:
                f.write(f"Kunci AES: {aes_key_text[:8]}...{aes_key_text[-8:]} (panjang: {len(aes_key_text)})\n")
                f.write(f"Kunci ChaCha20: {chacha_key_text[:8]}...{chacha_key_text[-8:]} (panjang: {len(chacha_key_text)})\n")
            
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

def display_images(original_rgb_array, original_gray_array, aes_encrypted_array, aes_decrypted_array,
                  chacha_encrypted_array, chacha_decrypted_array, image_path):
    """Menampilkan gambar dalam layout 3 baris: 
    Baris 1: Original RGB, Original Grayscale
    Baris 2: AES Encrypted, AES Decrypted  
    Baris 3: ChaCha20 Encrypted, ChaCha20 Decrypted"""
    try:
        # Konfigurasi matplotlib untuk tampilan yang lebih baik
        plt.style.use('default')
        fig, axes = plt.subplots(3, 2, figsize=(12, 15))
        fig.suptitle(f'Perbandingan AES-CBC vs ChaCha20 - {os.path.basename(image_path)}', 
                    fontsize=16, fontweight='bold')
        
        # Baris 1: Original images
        # Original RGB
        if len(original_rgb_array.shape) == 3:
            axes[0, 0].imshow(original_rgb_array)
        else:
            axes[0, 0].imshow(original_rgb_array, cmap='gray')
        axes[0, 0].set_title('Original Image (RGB)', fontweight='bold', fontsize=12)
        axes[0, 0].axis('off')
        axes[0, 0].text(0.02, 0.98, f'RGB\nSize: {original_rgb_array.shape}', 
                       transform=axes[0, 0].transAxes, verticalalignment='top',
                       bbox=dict(boxstyle='round', facecolor='blue', alpha=0.7), color='white')
        
        # Original Grayscale
        axes[0, 1].imshow(original_gray_array, cmap='gray', vmin=0, vmax=255)
        axes[0, 1].set_title('Original Image (Grayscale)', fontweight='bold', fontsize=12)
        axes[0, 1].axis('off')
        axes[0, 1].text(0.02, 0.98, f'Grayscale\nSize: {original_gray_array.shape}', 
                       transform=axes[0, 1].transAxes, verticalalignment='top',
                       bbox=dict(boxstyle='round', facecolor='gray', alpha=0.7), color='white')
        
        # Baris 2: AES-CBC
        # AES Encrypted
        axes[1, 0].imshow(aes_encrypted_array, cmap='gray', vmin=0, vmax=255)
        axes[1, 0].set_title('AES-CBC Encrypted', fontweight='bold', color='red', fontsize=12)
        axes[1, 0].axis('off')
        axes[1, 0].text(0.02, 0.98, 'AES-CBC\nEncrypted', 
                       transform=axes[1, 0].transAxes, verticalalignment='top', color='white',
                       bbox=dict(boxstyle='round', facecolor='red', alpha=0.8))
        
        # AES Decrypted
        axes[1, 1].imshow(aes_decrypted_array, cmap='gray', vmin=0, vmax=255)
        axes[1, 1].set_title('AES-CBC Decrypted', fontweight='bold', color='green', fontsize=12)
        axes[1, 1].axis('off')
        axes[1, 1].text(0.02, 0.98, 'AES-CBC\nDecrypted', 
                       transform=axes[1, 1].transAxes, verticalalignment='top', color='white',
                       bbox=dict(boxstyle='round', facecolor='green', alpha=0.8))
        
        # Baris 3: ChaCha20
        # ChaCha20 Encrypted
        axes[2, 0].imshow(chacha_encrypted_array, cmap='gray', vmin=0, vmax=255)
        axes[2, 0].set_title('ChaCha20 Encrypted', fontweight='bold', color='darkred', fontsize=12)
        axes[2, 0].axis('off')
        axes[2, 0].text(0.02, 0.98, 'ChaCha20\nEncrypted', 
                       transform=axes[2, 0].transAxes, verticalalignment='top', color='white',
                       bbox=dict(boxstyle='round', facecolor='darkred', alpha=0.8))
        
        # ChaCha20 Decrypted
        axes[2, 1].imshow(chacha_decrypted_array, cmap='gray', vmin=0, vmax=255)
        axes[2, 1].set_title('ChaCha20 Decrypted', fontweight='bold', color='darkgreen', fontsize=12)
        axes[2, 1].axis('off')
        axes[2, 1].text(0.02, 0.98, 'ChaCha20\nDecrypted', 
                       transform=axes[2, 1].transAxes, verticalalignment='top', color='white',
                       bbox=dict(boxstyle='round', facecolor='darkgreen', alpha=0.8))
        
        # Tambahkan informasi di bawah
        info_text = (
            "ANALISIS VISUAL PERBANDINGAN:\n"
            "• Baris 1: Gambar asli dalam format RGB dan Grayscale\n"
            "• Baris 2: Hasil enkripsi dan dekripsi dengan AES-CBC\n"
            "• Baris 3: Hasil enkripsi dan dekripsi dengan ChaCha20\n"
            "• Gambar decrypted harus identik dengan original grayscale"
        )
        fig.text(0.5, 0.02, info_text, ha='center', va='bottom', fontsize=10,
                bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8, pad=0.5))
        
        # Atur layout agar rapi
        plt.tight_layout()
        plt.subplots_adjust(top=0.93, bottom=0.15)
        
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

def encrypt_decrypt_compare(image_path, aes_key, chacha_key, aes_key_text=None, chacha_key_text=None):
    """
    Fungsi utama untuk memuat gambar, mengenkripsi dengan AES-CBC dan ChaCha20,
    mendekripsi, dan mengevaluasi perbandingan hasilnya.
    """
    # 1. Muat dan siapkan gambar
    try:
        # Baca gambar asli (RGB)
        original_image_rgb = Image.open(image_path)
        original_rgb_array = np.array(original_image_rgb)
        
        # Konversi ke grayscale untuk enkripsi
        original_image_gray = original_image_rgb.convert('L') 
        original_gray_array = np.array(original_image_gray)
        
        print(f"Gambar '{image_path}' berhasil dimuat.")
        print(f"  RGB shape: {original_rgb_array.shape}")
        print(f"  Grayscale shape: {original_gray_array.shape}")
    except FileNotFoundError:
        print(f"Error: File '{image_path}' tidak ditemukan.")
        return

    # 2. Siapkan parameter untuk kedua algoritma
    # Generate IV/nonce random untuk setiap enkripsi
    aes_iv = get_random_bytes(16)   # IV 128-bit untuk AES
    chacha_nonce = get_random_bytes(12) # Nonce 96-bit untuk ChaCha20

    print(f"\nMenggunakan kunci yang telah dikonfigurasi:")
    print(f"  AES Key: {'*' * 32} (32 bytes)")
    print(f"  ChaCha20 Key: {'*' * 32} (32 bytes)")

    # 3. Enkripsi dengan AES-CBC
    print("\n--- Enkripsi dengan AES-CBC ---")
    image_bytes = original_gray_array.tobytes()
    
    # Padding untuk AES (blok 16 byte)
    padded_data = pad(image_bytes, AES.block_size)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    aes_encrypted_bytes = aes_cipher.encrypt(padded_data)
    
    # Reshape untuk AES (ukuran bisa berubah karena padding)
    aes_encrypted_flat = np.frombuffer(aes_encrypted_bytes, dtype=np.uint8)
    # Potong ke ukuran asli untuk visualisasi
    aes_encrypted_visual = aes_encrypted_flat[:original_gray_array.size]
    aes_encrypted_array = aes_encrypted_visual.reshape(original_gray_array.shape)
    print(f"AES-CBC enkripsi selesai. Ukuran data: {len(aes_encrypted_bytes)} bytes")

    # 4. Enkripsi dengan ChaCha20
    print("--- Enkripsi dengan ChaCha20 ---")
    chacha_cipher = ChaCha20.new(key=chacha_key, nonce=chacha_nonce)
    chacha_encrypted_bytes = chacha_cipher.encrypt(image_bytes)
    chacha_encrypted_array = np.frombuffer(chacha_encrypted_bytes, dtype=np.uint8).reshape(original_gray_array.shape)
    print(f"ChaCha20 enkripsi selesai. Ukuran data: {len(chacha_encrypted_bytes)} bytes")

    # 5. Dekripsi AES-CBC
    print("--- Dekripsi dengan AES-CBC ---")
    aes_decipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    aes_decrypted_padded = aes_decipher.decrypt(aes_encrypted_bytes)
    aes_decrypted_bytes = unpad(aes_decrypted_padded, AES.block_size)
    aes_decrypted_array = np.frombuffer(aes_decrypted_bytes, dtype=np.uint8).reshape(original_gray_array.shape)
    print("AES-CBC dekripsi selesai.")

    # 6. Dekripsi ChaCha20
    print("--- Dekripsi dengan ChaCha20 ---")
    chacha_decipher = ChaCha20.new(key=chacha_key, nonce=chacha_nonce)
    chacha_decrypted_bytes = chacha_decipher.decrypt(chacha_encrypted_bytes)
    chacha_decrypted_array = np.frombuffer(chacha_decrypted_bytes, dtype=np.uint8).reshape(original_gray_array.shape)
    print("ChaCha20 dekripsi selesai.")

    # 7. Simpan semua gambar hasil
    base_name = os.path.splitext(image_path)[0]
    
    # Simpan original RGB dan grayscale
    original_rgb_path = f"{base_name}_original_RGB.png"
    original_gray_path = f"{base_name}_original_grayscale.png"
    aes_encrypted_path = f"{base_name}_AES_encrypted.png"
    chacha_encrypted_path = f"{base_name}_ChaCha20_encrypted.png"
    aes_decrypted_path = f"{base_name}_AES_decrypted.png"
    chacha_decrypted_path = f"{base_name}_ChaCha20_decrypted.png"

    # Save images
    if len(original_rgb_array.shape) == 3:
        Image.fromarray(original_rgb_array).save(original_rgb_path)
    else:
        Image.fromarray(original_rgb_array).save(original_rgb_path)
    
    Image.fromarray(original_gray_array).save(original_gray_path)
    Image.fromarray(aes_encrypted_array).save(aes_encrypted_path)
    Image.fromarray(chacha_encrypted_array).save(chacha_encrypted_path)
    Image.fromarray(aes_decrypted_array).save(aes_decrypted_path)
    Image.fromarray(chacha_decrypted_array).save(chacha_decrypted_path)
    
    print(f"\nGambar hasil disimpan:")
    print(f"  Original RGB: {original_rgb_path}")
    print(f"  Original Grayscale: {original_gray_path}")
    print(f"  AES encrypted: {aes_encrypted_path}")
    print(f"  ChaCha20 encrypted: {chacha_encrypted_path}")
    print(f"  AES decrypted: {aes_decrypted_path}")
    print(f"  ChaCha20 decrypted: {chacha_decrypted_path}")

    # 8. Evaluasi metrik untuk semua perbandingan (menggunakan grayscale)
    print("\n" + "="*60)
    print("|| HASIL EVALUASI METRIK PERBANDINGAN ||")
    print("="*60)

    all_metrics = {}

    # Validasi dekripsi AES
    print("\n--- VALIDASI AES-CBC ---")
    print("Original vs AES Decrypted (harus identik):")
    aes_validation = evaluate_metrics(original_gray_array, aes_decrypted_array)
    all_metrics["AES-CBC Validation (Original vs Decrypted)"] = aes_validation
    for key_metric, value in aes_validation.items():
        if key_metric == "PSNR" and value == float('inf'):
            print(f"  {key_metric:<26}: ∞ (Perfect match)")
        else:
            print(f"  {key_metric:<26}: {value}")

    # Validasi dekripsi ChaCha20
    print("\n--- VALIDASI ChaCha20 ---")
    print("Original vs ChaCha20 Decrypted (harus identik):")
    chacha_validation = evaluate_metrics(original_gray_array, chacha_decrypted_array)
    all_metrics["ChaCha20 Validation (Original vs Decrypted)"] = chacha_validation
    for key_metric, value in chacha_validation.items():
        if key_metric == "PSNR" and value == float('inf'):
            print(f"  {key_metric:<26}: ∞ (Perfect match)")
        else:
            print(f"  {key_metric:<26}: {value}")

    # Perbandingan enkripsi AES vs Original
    print("\n--- ANALISIS ENKRIPSI AES-CBC ---")
    print("Original vs AES Encrypted (harus sangat berbeda):")
    aes_encryption_analysis = evaluate_metrics(original_gray_array, aes_encrypted_array)
    all_metrics["AES-CBC Encryption Analysis (Original vs Encrypted)"] = aes_encryption_analysis
    for key_metric, value in aes_encryption_analysis.items():
        print(f"  {key_metric:<26}: {value}")

    # Perbandingan enkripsi ChaCha20 vs Original
    print("\n--- ANALISIS ENKRIPSI ChaCha20 ---")
    print("Original vs ChaCha20 Encrypted (harus sangat berbeda):")
    chacha_encryption_analysis = evaluate_metrics(original_gray_array, chacha_encrypted_array)
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
    save_metrics_to_file(all_metrics, image_path, aes_key_text, chacha_key_text)
    
    # Tampilkan semua gambar dalam layout 3x2
    print("\nMenampilkan perbandingan gambar dalam layout 3x2...")
    display_images(original_rgb_array, original_gray_array, aes_encrypted_array, aes_decrypted_array,
                  chacha_encrypted_array, chacha_decrypted_array, image_path)


if __name__ == '__main__':
    print("=== PROGRAM PERBANDINGAN ENKRIPSI AES-CBC vs ChaCha20 ===\n")
    
    # Step 1: Konfigurasi kunci enkripsi
    print("Step 1: Konfigurasi kunci enkripsi...")
    key_config = get_encryption_keys()
    
    if key_config["cancelled"]:
        print("Konfigurasi kunci dibatalkan. Program dihentikan.")
    else:
        print("Kunci enkripsi berhasil dikonfigurasi!")
        
        # Step 2: Pilih file gambar
        print("\nStep 2: Pilih file gambar...")
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
                    # Step 3: Jalankan proses perbandingan enkripsi dan evaluasi
                    print("\nStep 3: Memulai proses enkripsi dan analisis...")
                    encrypt_decrypt_compare(input_image_file, key_config["aes_key"], key_config["chacha_key"],
                                          key_config["aes_key_text"], key_config["chacha_key_text"])
                    
                    print("\n" + "="*60)
                    print("PROSES PERBANDINGAN SELESAI!")
                    print("="*60)
                    print("Hasil yang telah dibuat:")
                    print("✓ 6 gambar hasil (RGB original, grayscale original, 2 encrypted, 2 decrypted)")
                    print("✓ File metrik perbandingan dalam format .txt")
                    print("✓ Tampilan visual perbandingan dalam layout 3x2")
                    print(f"✓ Kunci yang digunakan telah disimpan dalam metrik file")
                    
                except Exception as e:
                    print(f"Error saat memproses gambar: {e}")
                    messagebox.showerror("Error", f"Terjadi kesalahan: {str(e)}")