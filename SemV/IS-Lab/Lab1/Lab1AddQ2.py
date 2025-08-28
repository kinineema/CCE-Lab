def vigenere_encrypt(plaintext, keyword):
    plaintext = plaintext.replace(" ", "").upper()
    keyword = keyword.upper()
    key_stream = (keyword * (len(plaintext) // len(keyword) + 1))[:len(plaintext)]
    ciphertext = ""

    for p_char, k_char in zip(plaintext, key_stream):
        p = ord(p_char) - ord('A')
        k = ord(k_char) - ord('A')
        c = (p + k) % 26
        ciphertext += chr(c + ord('A'))

    return ciphertext

plaintext = "Life is full of surprises"
keyword = "HEALTH"

encrypted = vigenere_encrypt(plaintext, keyword)
print("Encrypted message:", encrypted)
