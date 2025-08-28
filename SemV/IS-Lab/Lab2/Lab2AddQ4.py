from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify

key_hex = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
key = unhexlify(key_hex)

plaintext = b"Encryption Strength"
block_size = AES.block_size  # 16 bytes

cipher = AES.new(key, AES.MODE_ECB)

padded_plaintext = pad(plaintext, block_size)
ciphertext = cipher.encrypt(padded_plaintext)
print("Ciphertext (hex):", ciphertext.hex())

decrypted_padded = cipher.decrypt(ciphertext)
decrypted = unpad(decrypted_padded, block_size)
print("Decrypted text:", decrypted.decode())