def mod_inverse(a, m):
    # Extended Euclidean Algorithm to find modular inverse
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def affine_decrypt(ciphertext, a, b):
    plaintext = ''
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return "Invalid key (no modular inverse)"

    for char in ciphertext:
        if char.isalpha():
            y = ord(char) - ord('A')
            x = (a_inv * (y - b)) % 26
            plaintext += chr(x + ord('A'))
        else:
            plaintext += char
    return plaintext


# Given values
ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
a = 5
b = 6

decrypted = affine_decrypt(ciphertext, a, b)
print("Decrypted message:", decrypted)
