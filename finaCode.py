import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np
from scipy.io.wavfile import read, write
import hashlib
import os
from Crypto.Cipher import AES

# Fungsi enkripsi AES
def encrypt_aes(word, key):
    word_bytes = word.encode('utf-8')
    iv = os.urandom(16)  # Menghasilkan IV acak dengan panjang 16 byte
    encryption_key = hashlib.md5(key.encode('utf-8')).digest()

    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    padding = AES.block_size - len(word_bytes) % AES.block_size
    word_bytes += bytes([padding]) * padding
    encrypted_data = iv + cipher.encrypt(word_bytes)
    
    return encrypted_data

# Fungsi dekripsi AES
def decrypt_aes(ciphertext, key):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]

    encryption_key = hashlib.md5(key.encode('utf-8')).digest()

    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)

    padding = decrypted_data[-1]
    decrypted_data = decrypted_data[:-padding]
    string_data = decrypted_data.decode('utf-8')

    return string_data

# Fungsi steganografi untuk menyisipkan pesan ke dalam audio
def hide_message_in_audio(audio_file_path, message, key):
    # Baca file audio
    sampling_rate, audio_samples = read(audio_file_path)
     
    
    # Pastikan tipe data sampel adalah int16
    if audio_samples.dtype != np.int16:
        raise ValueError("File audio harus dalam format int16")
    
    # Enkripsi pesan
    encrypted_message = encrypt_aes(message, key)
    
    # Konversi panjang pesan terenkripsi, dan pesan terenkripsi ke biner
    message_length = len(encrypted_message)
    message_length_binary = format(message_length, '032b')  # 32 bit untuk panjang pesan
    message_binary = ''.join(format(byte, '08b') for byte in encrypted_message)
    
    # Gabungkan panjang pesan dengan pesan itu sendiri
    combined_message_binary = message_length_binary + message_binary
    
    # Cek panjang pesan
    if len(combined_message_binary) > len(audio_samples):
        raise ValueError("Pesan terlalu panjang untuk disisipkan ke dalam audio")
    
    # Sisipkan pesan
    for i, bit in enumerate(combined_message_binary):
        if bit == '1':
            audio_samples[i] |= 1
        else:
            audio_samples[i] &= ~1
    
    # Simpan file audio baru
    output_file_path = os.path.splitext(audio_file_path)[0] + "_stego.wav"
    write(output_file_path, sampling_rate, audio_samples)
    return output_file_path

# Fungsi steganografi untuk mengekstrak pesan dari audio
def extract_message_from_audio(stego_file, key):
    # Baca file audio
    sampling_rate, audio_samples = read(stego_file)
    
    # Jika audio stereo, gunakan hanya satu saluran
    if audio_samples.ndim > 1:
        audio_samples = audio_samples[:, 0]
    
    # Ekstrak panjang pesan (32 bit pertama)
    message_length_bits = ''.join(str(audio_samples[i] & 1) for i in range(32))
    message_length = int(message_length_bits, 2)
    
    # Ekstrak bit pesan terenkripsi
    message_bits = ''.join(str(audio_samples[i + 32] & 1) for i in range(message_length * 8))
    
    # Konversi bit ke byte terenkripsi
    encrypted_message = bytes(int(message_bits[i:i+8], 2) for i in range(0, len(message_bits), 8))
    
    # Dekripsi pesan
    message = decrypt_aes(encrypted_message, key)
    
    return message

# Fungsi untuk menampilkan informasi audio
def show_audio_info(audio_file_path, info_label):
    sampling_rate, audio_samples = read(audio_file_path)
    num_channels = audio_samples.shape[1] if audio_samples.ndim > 1 else 1
    duration = len(audio_samples) / sampling_rate
    info_text = f"Sample Rate: {sampling_rate} Hz\nChannels: {num_channels}\nDuration: {duration:.2f} seconds"
    info_label.config(text=info_text)

# Fungsi untuk membuka jendela Hide Message
def open_hide_message_window():
    hide_window = tk.Toplevel(root)
    hide_window.title("Hide Message in Audio")
    
    tk.Label(hide_window, text="Browse WAV File:").grid(row=0, column=0, padx=10, pady=10)
    wav_file_entry = tk.Entry(hide_window, width=50)
    wav_file_entry.grid(row=0, column=1, padx=10, pady=10)
    
    def browse_file():
        file_path = filedialog.askopenfilename(filetypes=[("WAV files", "*.wav")])
        wav_file_entry.insert(0, file_path)
        show_audio_info(file_path, audio_info_label)

    browse_button = tk.Button(hide_window, text="Browse", command=browse_file)
    browse_button.grid(row=0, column=2, padx=10, pady=10)

    tk.Label(hide_window, text="Secret Message:").grid(row=1, column=0, padx=10, pady=10)
    message_entry = tk.Entry(hide_window, width=50)
    message_entry.grid(row=1, column=1, padx=10, pady=10)

    tk.Label(hide_window, text="Key:").grid(row=2, column=0, padx=10, pady=10)
    key_entry = tk.Entry(hide_window, width=50)
    key_entry.grid(row=2, column=1, padx=10, pady=10)

    audio_info_label = tk.Label(hide_window, text="")
    audio_info_label.grid(row=3, column=0, columnspan=3, padx=10, pady=10)

    def hide_message():
        wav_file = wav_file_entry.get()
        message = message_entry.get()
        key = key_entry.get()
        
        if not wav_file or not message or not key:
            messagebox.showerror("Error", "Please provide WAV file, secret message, and encryption key")
            return
        
        try:
            output_file = hide_message_in_audio(wav_file, message, key)
            messagebox.showinfo("Success", f"Message hidden in audio file successfully.\nSaved as {output_file}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    hide_button = tk.Button(hide_window, text="Hide", command=hide_message)
    hide_button.grid(row=4, column=1, pady=20)

# Fungsi untuk membuka jendela Show Message
def open_show_message_window():
    show_window = tk.Toplevel(root)
    show_window.title("Show Hidden Message")

    tk.Label(show_window, text="Browse Stego Audio File:").grid(row=0, column=0, padx=10, pady=10)
    stego_file_entry = tk.Entry(show_window, width=50)
    stego_file_entry.grid(row=0, column=1, padx=10, pady=10)
    
    def browse_stego_file():
        file_path = filedialog.askopenfilename(filetypes=[("WAV files", "*.wav")])
        stego_file_entry.insert(0, file_path)
        show_audio_info(file_path, audio_info_label)

    browse_button = tk.Button(show_window, text="Browse", command=browse_stego_file)
    browse_button.grid(row=0, column=2, padx=10, pady=10)

    tk.Label(show_window, text="Key:").grid(row=1, column=0, padx=10, pady=10)
    key_entry = tk.Entry(show_window, width=50)
    key_entry.grid(row=1, column=1, padx=10, pady=10)

    audio_info_label = tk.Label(show_window, text="")
    audio_info_label.grid(row=2, column=0, columnspan=3, padx=10, pady=10)

    def show_message():
        stego_file = stego_file_entry.get()
        key = key_entry.get()

        if not stego_file or not key:
            messagebox.showerror("Error", "Please provide stego audio file and encryption key")
            return
        
        try:
            message = extract_message_from_audio(stego_file, key)
            messagebox.showinfo("Extracted Message", f"The hidden message is: {message}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    show_button = tk.Button(show_window, text="Show", command=show_message)
    show_button.grid(row=3, column=1, pady=20)

# Inisialisasi jendela utama
root = tk.Tk()
root.title("Audio Steganography")
root.geometry("400x300")

hide_message_button = tk.Button(root, text="Hide Message", width=20, height=4, command=open_hide_message_window)
hide_message_button.pack(pady=20)

show_message_button = tk.Button(root, text="Show Message", width=20, height=4, command=open_show_message_window)
show_message_button.pack(pady=20)

root.mainloop()
