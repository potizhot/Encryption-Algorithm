"""Terminal entry point for the DES-CBC + HMAC-SHA256 prototype."""

import secrets

import authenticated_des


def read_des_key(allow_generate=False):
    prompt = "DES key (16 hex digits"
    prompt += ", Enter to generate" if allow_generate else ""
    text = input(prompt + "): ").strip()

    if allow_generate and not text:
        return secrets.randbits(64)
    if len(text) != 16:
        raise ValueError("DES key must have exactly 16 hexadecimal digits")
    return int(text, 16)


def read_mac_key():
    text = input("HMAC key (64 hex digits): ").strip()
    if len(text) != 64:
        raise ValueError("HMAC key must have exactly 64 hexadecimal digits")
    return bytes.fromhex(text)


def main():
    print("DES-CBC + HMAC-SHA256")
    print("1. Encrypt a message")
    print("2. Decrypt a packet")
    choice = input("Choose 1 or 2: ").strip()
    print()

    try:
        if choice == "1":
            message = input("Message (up to 255 characters): ")
            des_key = read_des_key(allow_generate=True)
            mac_key = secrets.token_bytes(32)

            packet = authenticated_des.encrypt_message(message, des_key, mac_key)
            print()
            print("DES key:          ", f"{des_key:016X}")
            print("HMAC key:         ", mac_key.hex().upper())
            print("IV:               ", packet[:8].hex().upper())
            print("Ciphertext:       ", packet[8:-32].hex().upper())
            print("HMAC-SHA256 tag:  ", packet[-32:].hex().upper())
            print("Full packet:      ", packet.hex().upper())
            print("Verified plaintext:", authenticated_des.decrypt_message(packet, des_key, mac_key))

            tampered = bytearray(packet)
            tampered[8] ^= 1  # Change one ciphertext bit for the demonstration.
            try:
                authenticated_des.decrypt_message(bytes(tampered), des_key, mac_key)
            except ValueError:
                print("Tamper test:       Changed ciphertext rejected")

        elif choice == "2":
            packet = bytes.fromhex(input("Full packet (hex): ").strip())
            des_key = read_des_key()
            mac_key = read_mac_key()
            message = authenticated_des.decrypt_message(packet, des_key, mac_key)
            print("Authentication:    Passed")
            print("Decrypted message:", message)

        else:
            print("Choose 1 or 2.")

    except ValueError as error:
        print("Error:", error)


if __name__ == "__main__":
    main()
