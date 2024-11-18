import numpy as np
import wave

def read_wav(file_path):
    with wave.open(file_path, 'rb') as wav_file:
        n_channels = wav_file.getnchannels()
        sample_width = wav_file.getsampwidth()
        n_frames = wav_file.getnframes()
        frames = wav_file.readframes(n_frames)
        samples = np.frombuffer(frames, dtype=np.int16)
        return samples

# Contoh penggunaan
original_file = 'audio1.wav'
compressed_file = 'audio1_stego.wav'

def calculate_mse(original_samples, compressed_samples):
    return np.mean((original_samples - compressed_samples) ** 2)

def calculate_psnr(mse, max_val):
    if mse == 0:
        return float('inf')  # PSNR is infinite if there is no error
    return 10 * np.log10(max_val**2 / mse)


original_samples = read_wav(original_file)
compressed_samples = read_wav(compressed_file)

mse = calculate_mse(original_samples, compressed_samples)
psnr = calculate_psnr(mse, 32767)

print(f"PSNR: {psnr} dB")
print(f"mse: {mse}")
