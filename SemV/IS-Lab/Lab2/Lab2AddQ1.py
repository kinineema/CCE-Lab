import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt

messages = [
    b"Hello, this is message 1.",
    b"Message two is a bit longer than one.",
    b"Short msg 3.",
    b"Here comes message number four with more text.",
    b"Fifth and final message to encrypt."
]

des_key = b"8bytekey"  # DES key is exactly 8 bytes
aes_keys = {
    128: get_random_bytes(16),
    192: get_random_bytes(24),
    256: get_random_bytes(32)
}

modes = ["ECB", "CBC", "CFB", "OFB", "CTR"]

def create_cipher(alg, key, mode, iv=None):
    if alg == "DES":
        if mode == "CTR":
            return DES.new(key, DES.MODE_CTR, nonce=b'')
        elif mode == "ECB":
            return DES.new(key, DES.MODE_ECB)
        else:
            return DES.new(key, getattr(DES, f"MODE_{mode}"), iv=iv)
    else:  # AES
        if mode == "CTR":
            return AES.new(key, AES.MODE_CTR, nonce=b'')
        elif mode == "ECB":
            return AES.new(key, AES.MODE_ECB)
        else:
            return AES.new(key, getattr(AES, f"MODE_{mode}"), iv=iv)

def encrypt_message(alg, key, mode_name, message):
    block_size = DES.block_size if alg == "DES" else AES.block_size
    iv = get_random_bytes(block_size) if mode_name not in ["ECB", "CTR"] else None
    cipher = create_cipher(alg, key, mode_name, iv)
    padded_msg = pad(message, block_size)
    return cipher.encrypt(padded_msg)

results = {
    "DES": {mode: [] for mode in modes},
    "AES-128": {mode: [] for mode in modes},
    "AES-192": {mode: [] for mode in modes},
    "AES-256": {mode: [] for mode in modes}
}

iterations = 100

for alg in results:
    key = des_key if alg == "DES" else aes_keys[int(alg.split('-')[1])]
    for mode in modes:
        for msg in messages:
            start = time.perf_counter()
            for _ in range(iterations):
                encrypt_message("DES" if alg == "DES" else "AES", key, mode, msg)
            elapsed = (time.perf_counter() - start) / iterations
            results[alg][mode].append(elapsed * 1e6)  # microseconds

# Plotting average time per mode per algorithm
for alg in results:
    avg_times = [sum(results[alg][mode])/len(results[alg][mode]) for mode in modes]
    plt.plot(modes, avg_times, marker='o', label=alg)

plt.title("Encryption Time Comparison (μs)")
plt.xlabel("Mode of Operation")
plt.ylabel("Average Encryption Time (microseconds)")
plt.legend()
plt.grid(True)
plt.show()
