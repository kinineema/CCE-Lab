def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    key = key.upper()
    ciphertext = ""

    # Repeat key to match length
    full_key = (key * (len(plaintext) // len(key) + 1))[:len(plaintext)]
    # Here, len(ciphertext)//len(key) + 1 ~ No of times that the key needs to be repeated to get Plaintext
    # Then, we multiply key with that value
    # Further, we slice the key with len(plaintext) ==> 25/7 = 3 +1 = 4 ==> 4* 7(key) = 28 and then slice 25
    for p_char, k_char in zip(plaintext, full_key):
        shift = (ord(p_char) - ord('A') + ord(k_char) - ord('A')) % 26
        ciphertext += chr(shift + ord('A'))

    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    plaintext = ""
    full_key = (key * (len(ciphertext) // len(key) + 1))[:len(ciphertext)]
    for c_char, k_char in zip(ciphertext, full_key):
        shift = (ord(c_char) - ord('A') - (ord(k_char) - ord('A'))) % 26
        plaintext += chr(shift + ord('A'))
    return plaintext

def autokey_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    key_stream = [key] + [ord(c) - ord('A') for c in plaintext[:-1]]
    ciphertext = ""

    for i, char in enumerate(plaintext):
        p = ord(char) - ord('A')
        k = key_stream[i]
        c = (p + k) % 26
        ciphertext += chr(c + ord('A'))

    return ciphertext

def autokey_decrypt(ciphertext, key):
    ciphertext = ciphertext.replace(" ", "").upper()
    plaintext = ""
    key_stream = [key]

    for i, char in enumerate(ciphertext):
        c = ord(char) - ord('A')
        k = key_stream[i]
        p = (c - k) % 26
        plaintext += chr(p + ord('A'))
        key_stream.append(p)  # Append recovered plaintext to key stream

    return plaintext

message="the house is being sold tonight"
key="dollars"
print("Vigenere Cipher:")
encrypted_message=vigenere_encrypt(message,key)
print("Encrypted message:", encrypted_message)
decrypted_message=vigenere_decrypt(encrypted_message,key)
print("Decrypted message:", decrypted_message)

autokey=7
print("AutoKey Cipher:")
encrypted_message=autokey_encrypt(message,autokey)
print("Encrypted message:", encrypted_message)
decrypted_message=autokey_decrypt(encrypted_message,autokey)
print("Decrypted message:", decrypted_message)
