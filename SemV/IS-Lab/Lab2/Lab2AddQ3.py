from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

key = b"A1B2C3D4"
iv = b"12345678"
plaintext = b"Secure Communication"

cipher = DES.new(key, DES.MODE_CBC, iv)
padded_text = pad(plaintext, DES.block_size)
ciphertext = cipher.encrypt(padded_text)
print("Ciphertext (hex):", ciphertext.hex())

# Decrypt
decipher = DES.new(key, DES.MODE_CBC, iv)
decrypted_padded = decipher.decrypt(ciphertext)
decrypted = unpad(decrypted_padded, DES.block_size)
print("Decrypted text:", decrypted.decode())