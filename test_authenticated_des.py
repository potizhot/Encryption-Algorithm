"""Run the authenticated DES prototype checks: python test_authenticated_des.py."""

import secrets

import authenticated_des
import des


des_key = 0x133457799BBCDFF1
mac_key = secrets.token_bytes(32)


def expect_authentication_failure(packet, key):
    try:
        authenticated_des.decrypt_message(packet, des_key, key)
    except ValueError as error:
        assert str(error) == "Authentication failed"
    else:
        raise AssertionError("Invalid packet or HMAC key was accepted")


# Test messages with empty text, spaces, Unicode, and several 8-byte blocks.
messages = ["", "Dasalla Qpal", "Hello, world!", "Kamusta 🌏", "ABCDEFGH" * 8]
messages += ["A" * length for length in range(1, 101)]

for message in messages:
    packet = authenticated_des.encrypt_message(message, des_key, mac_key)
    assert authenticated_des.decrypt_message(packet, des_key, mac_key) == message
print(f"Encrypt/decrypt: {len(messages)} messages restored")

# A new IV should give different encrypted output for the same message.
first = authenticated_des.encrypt_message("ABCDEFGH" * 8, des_key, mac_key)
second = authenticated_des.encrypt_message("ABCDEFGH" * 8, des_key, mac_key)
assert first != second
print("Fresh IV:         same message produced different packets")

# ECB reveals repeated blocks; CBC should give different ciphertext blocks.
ecb = des.encrypt_message("ABCDEFGH" * 8, des_key)
cbc = first[8:-32]
assert ecb[:8] == ecb[8:16]
assert cbc[:8] != cbc[8:16]
print("Repeated blocks:  ECB repeated a block; CBC did not")

# Changing any byte of the IV, ciphertext, or tag must fail authentication.
for position in range(len(first)):
    tampered = bytearray(first)
    tampered[position] ^= 1
    expect_authentication_failure(bytes(tampered), mac_key)
print(f"Tampering:        all {len(first)} altered packet bytes rejected")

expect_authentication_failure(first, secrets.token_bytes(32))
print("Wrong HMAC key:   rejected")
