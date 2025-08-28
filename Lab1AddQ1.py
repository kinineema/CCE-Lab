def caesar_decrypt(ciphertext, key):
    result = ''
    for char in ciphertext:
        if char.isupper():
            decrypted = chr(((ord(char) - ord('A') - key) % 26) + ord('A'))
            result += decrypted
        else:
            result += char  # keep non-alphabetic characters as-is
    return result

ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

print("Trying Caesar cipher decryption with keys near 13:")
for key in range(10, 17):
    decrypted = caesar_decrypt(ciphertext, key)
    print(f"Key = {key}: {decrypted}")

decrypted=caesar_decrypt(ciphertext, 11)
print("\n\nDecrypted message Key = 11: ", decrypted)
