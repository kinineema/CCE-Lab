from Crypto.Cipher import DES

def des_cipher(key):
    return DES.new(key.encode('utf-8'), DES.MODE_ECB)

def despad_ptext(text):
    n = len(text) % 8
    if n != 0:
        return text + (' ' * (8 - n))
    else:
        return text

def des_en(ptext, key):
    cipher = des_cipher(key)
    ptext = despad_ptext(ptext).encode('utf-8')
    return cipher.encrypt(ptext)

def des_de(ctext, key):
    cipher = des_cipher(key)
    return cipher.decrypt(ctext).decode('utf-8').rstrip()

def despad_key(key):
    return key.ljust(8)[:8]


print("Welcome to DES (Original)")
ptext = input("Enter plaintext: ")
despad_ptext(ptext)
key = input("Enter key: ")
key = despad_key(key)
ctext = des_en(ptext, key)
print("Your ciphertext: ", ctext)
print("Your decrypted plaintext: ", des_de(ctext, key))

