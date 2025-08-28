from Crypto.Cipher import AES

key_hex = "0123456789ABCDEF0123456789ABCDEF"
key = bytes.fromhex(key_hex)
nonce = b"\x00" * 8
plaintext = b"Cryptography Lab Exercise"

cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
ciphertext = cipher.encrypt(plaintext)
print("Ciphertext (hex):", ciphertext.hex())

decipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
decrypted = decipher.decrypt(ciphertext)
print("Decrypted text:", decrypted.decode())
