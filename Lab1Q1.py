def encrypt_additive_cipher(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()  # Remove spaces and uppercase
    ciphertext = ""

    for char in plaintext:
        if char.isalpha():
            # Shift char by key positions
            shifted = (ord(char) - ord('A') + key) % 26 + ord('A')
            ciphertext += chr(shifted)
        else:
            ciphertext += char  # Keep non-alphabetic as is (if any)

    return ciphertext


def decrypt_additive_cipher(ciphertext, key):
    plaintext = ""

    for char in ciphertext:
        if char.isalpha():
            # Reverse shift by key positions
            shifted = (ord(char) - ord('A') - key) % 26 + ord('A')
            plaintext += chr(shifted)
        else:
            plaintext += char

    return plaintext

def mod_inverse(key, m=26):
    # Find modular inverse of key mod m using Extended Euclidean Algorithm
    for i in range(1, m):
        if (key * i) % m == 1:
            return i
    raise ValueError("No modular inverse found")

def encrypt_multiplicative_cipher(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            x = ord(char) - ord('A')
            y = (x * key) % 26
            ciphertext += chr(y + ord('A'))
        else:
            ciphertext += char
    return ciphertext

def decrypt_multiplicative_cipher(ciphertext, key):
    plaintext = ""
    key_inv = mod_inverse(key)
    for char in ciphertext:
        if char.isalpha():
            y = ord(char) - ord('A')
            x = (y * key_inv) % 26
            plaintext += chr(x + ord('A'))
        else:
            plaintext += char
    return plaintext

def encrypt_affine_cipher(plaintext, affine_key1,affine_key2):
    plaintext = plaintext.replace(" ", "").upper()
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            x=((ord(char) - ord('A'))*affine_key1)%26
            y=((x + affine_key2)%26)+ord('A')
            ciphertext += chr(y)
        else:
            ciphertext += char
    return ciphertext

def decrypt_affine_cipher(ciphertext, key1, key2):
    plaintext = ""
    key_inv = mod_inverse(key1)
    for char in ciphertext:
        if char.isalpha():
            y = ord(char) - ord('A')
            x = (key_inv * ((y - key2) % 26)) % 26
            plaintext += chr(x + ord('A'))
        else:
            plaintext += char
    return plaintext


# Main program
message = "I am learning information security"
key1 = 20

print("Additive Cipher:")
encrypted_message = encrypt_additive_cipher(message, key1)
print("Encrypted message:", encrypted_message)

decrypted_message = decrypt_additive_cipher(encrypted_message, key1)
print("Decrypted message:", decrypted_message)

key2 = 15
print("Multiplicative Cipher:")

encrypted_message = encrypt_multiplicative_cipher(message, key2)
print("Encrypted message:", encrypted_message)

decrypted_message = decrypt_multiplicative_cipher(encrypted_message, key2)
print("Decrypted message:", decrypted_message)

key3=15
key4=20
print("Affine Cipher:")
encrypted_message = encrypt_affine_cipher(message,key3,key4)
print("Encrypted message:", encrypted_message)
decrypted_message = decrypt_affine_cipher(encrypted_message, key3,key4)
print("Decrypted message:", decrypted_message)