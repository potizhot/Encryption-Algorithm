import des

# example plaintext message
message = "Dasalla Qpal"
# message = input("Enter a message you want to encrypt (255 max): ")
# if len(message) > 254:
#     raise ValueError("Max length is 255")

# example key
key = 0xD4AAE705DDE1A60A
# key_text = input("Enter a 16-digit Hex DES key: ").strip()
# if len(key_text) != 16:
#     raise ValueError("Enter exactly 16 hexadecimal digits")
# key = int(key_text, 16)

encrypted = des.encrypt_message(message, key)
decrypted = des.decrypt_message(encrypted, key)

binary_output = "".join(f"{byte:08b}" for byte in encrypted)
print(f"Ciphertext (binary): {binary_output}")

print(f"Message:    {message}")
print(f"Ciphertext: {encrypted.hex()}")
print(f"Decrypted Text: {decrypted}")