from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from binascii import unhexlify, hexlify

key_hex = "A1B2C3D4E5F60708"
key = unhexlify(key_hex)

block1_hex = "54686973206973206120636f6e666964656e7469616c206d657373616765"
block2_hex = "416e64207468697320697320746865207365636f6e6420626c6f636b"

block1 = unhexlify(block1_hex)
block2 = unhexlify(block2_hex)

cipher = DES.new(key, DES.MODE_ECB)

# DES block size is 8 bytes, pad to multiple of 8
block1_padded = pad(block1, DES.block_size)
block2_padded = pad(block2, DES.block_size)

ct1 = cipher.encrypt(block1_padded)
ct2 = cipher.encrypt(block2_padded)

print("Ciphertext Block1 (hex):", hexlify(ct1).decode())
print("Ciphertext Block2 (hex):", hexlify(ct2).decode())

pt1_padded = cipher.decrypt(ct1)
pt2_padded = cipher.decrypt(ct2)

pt1 = unpad(pt1_padded, DES.block_size)
pt2 = unpad(pt2_padded, DES.block_size)

print("Decrypted Block1:", pt1.decode())
print("Decrypted Block2:", pt2.decode())
