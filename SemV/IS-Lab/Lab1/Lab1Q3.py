def create_playfair_matrix(key):
    key = key.upper().replace('J', 'I')
    seen = set()
    matrix = []

    for char in key:
        if char.isalpha() and char not in seen:
            seen.add(char)
            matrix.append(char)

    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":  # Note: J is excluded
        if char not in seen:
            seen.add(char)
            matrix.append(char)

    # Convert to 5x5 matrix
    return [matrix[i:i+5] for i in range(0, 25, 5)]


def find_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None


def prepare_text(text):
    text = text.upper().replace("J", "I").replace(" ", "")
    prepared = []
    i = 0
    while i < len(text):
        a = text[i]
        b = 'X'
        if i + 1 < len(text):
            b = text[i + 1]
        if a == b:
            prepared.append(a + 'X')
            i += 1
        else:
            prepared.append(a + b)
            i += 2
    if len(prepared[-1]) == 1:
        prepared[-1] += 'X'
    return prepared


def playfair_encrypt(message, key):
    matrix = create_playfair_matrix(key)
    digraphs = prepare_text(message)
    ciphertext = ""

    for pair in digraphs:
        a, b = pair[0], pair[1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:  # Same row
            ciphertext += matrix[row1][(col1 + 1) % 5]
            ciphertext += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:  # Same column
            ciphertext += matrix[(row1 + 1) % 5][col1]
            ciphertext += matrix[(row2 + 1) % 5][col2]
        else:  # Rectangle
            ciphertext += matrix[row1][col2]
            ciphertext += matrix[row2][col1]

    return ciphertext

def playfair_decrypt(ciphertext, key):
    matrix = create_playfair_matrix(key)
    plaintext = ""

    i = 0
    while i < len(ciphertext):
        a = ciphertext[i]
        b = ciphertext[i+1]
        row1, col1 = find_position(matrix, a)
        row2, col2 = find_position(matrix, b)

        if row1 == row2:  # Same row
            plaintext += matrix[row1][(col1 - 1) % 5]
            plaintext += matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:  # Same column
            plaintext += matrix[(row1 - 1) % 5][col1]
            plaintext += matrix[(row2 - 1) % 5][col2]
        else:  # Rectangle
            plaintext += matrix[row1][col2]
            plaintext += matrix[row2][col1]

        i += 2

    return plaintext

message = "The key is hidden under the door pad"
key = "GUIDANCE"

encrypted = playfair_encrypt(message, key)
print("Encrypted message:", encrypted)

decrypted = playfair_decrypt(encrypted, key)  # <-- FIXED
print("Decrypted message:", decrypted)
