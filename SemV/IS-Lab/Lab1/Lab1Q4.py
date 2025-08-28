import numpy as np


def preprocess_text(text):
    text = text.upper().replace(" ", "")
    if len(text) % 2 != 0:
        text += "X"
    return text


def text_to_numbers(text):
    return [ord(c) - ord('A') for c in text]


def numbers_to_text(numbers):
    return ''.join(chr(n + ord('A')) for n in numbers)


def modinv(a, m):
    # Modular inverse using Extended Euclidean Algorithm
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None


def matrix_modinv_2x2(matrix, mod):
    a, b = matrix[0]
    c, d = matrix[1]
    det = (a * d - b * c) % mod
    det_inv = modinv(det, mod)
    if det_inv is None:
        raise ValueError("Matrix is not invertible modulo", mod)

    # Inverse of 2x2 matrix
    inv_matrix = np.array([[d, -b], [-c, a]]) * det_inv
    return inv_matrix % mod


def hill_encrypt(plaintext, key_matrix):
    plaintext = preprocess_text(plaintext)
    plain_nums = text_to_numbers(plaintext)
    ciphertext = ""

    for i in range(0, len(plain_nums), 2):
        pair = np.array([[plain_nums[i]], [plain_nums[i + 1]]])
        product = np.dot(key_matrix, pair) % 26
        ciphertext += numbers_to_text(product.flatten())

    return ciphertext


def hill_decrypt(ciphertext, key_matrix):
    cipher_nums = text_to_numbers(ciphertext)
    inverse_matrix = matrix_modinv_2x2(key_matrix, 26)
    plaintext = ""

    for i in range(0, len(cipher_nums), 2):
        pair = np.array([[cipher_nums[i]], [cipher_nums[i + 1]]])
        product = np.dot(inverse_matrix, pair) % 26
        plaintext += numbers_to_text(product.flatten())

    return plaintext


# Key matrix: [[3, 3], [2, 7]]
key_matrix = np.array([[3, 3], [2, 7]])
message = "We live in an insecure world"

# Encrypt
encrypted = hill_encrypt(message, key_matrix)
print("Encrypted message:", encrypted)

# Decrypt
decrypted = hill_decrypt(encrypted, key_matrix)
print("Decrypted message:", decrypted)
