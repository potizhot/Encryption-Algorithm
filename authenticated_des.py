"""Modified DES-CBC with HMAC-SHA256 for an educational terminal prototype

Packet format: 8-byte IV | DES ciphertext | 32-byte HMAC tag
The block cipher uses the added rotation-and-XOR step in modified_des.py
"""

import hashlib
import hmac
import secrets

import modified_des as des


BLOCK_SIZE = 8
TAG_SIZE = 32


def check_keys(des_key: int, mac_key: bytes) -> None:
    if not isinstance(des_key, int) or not 0 <= des_key < (1 << 64):
        raise ValueError("DES key must be a 64-bit integer")
    if not isinstance(mac_key, bytes) or len(mac_key) < 32:
        raise ValueError("HMAC key must contain at least 32 bytes")


def encrypt_message(message: str, des_key: int, mac_key: bytes) -> bytes:
    # Encrypt text, then authenticate the IV and ciphertext
    check_keys(des_key, mac_key)
    plaintext = des.prepare_message(message)  # UTF-8 plus 8-byte padding
    iv = secrets.token_bytes(BLOCK_SIZE)
    previous = iv
    ciphertext = bytearray()

    for start in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[start:start + BLOCK_SIZE]
        mixed = int.from_bytes(block, "big") ^ int.from_bytes(previous, "big")
        encrypted = des.encrypt_block(mixed, des_key).to_bytes(BLOCK_SIZE, "big")
        ciphertext.extend(encrypted)
        previous = encrypted

    data = iv + bytes(ciphertext)
    tag = hmac.new(mac_key, data, hashlib.sha256).digest()
    return data + tag


def decrypt_message(packet: bytes, des_key: int, mac_key: bytes) -> str:
    # Check authenticity first, decrypt only when the tag matches
    check_keys(des_key, mac_key)
    if not isinstance(packet, bytes) or len(packet) < BLOCK_SIZE * 2 + TAG_SIZE:
        raise ValueError("Invalid packet length")

    data = packet[:-TAG_SIZE]
    received_tag = packet[-TAG_SIZE:]
    if (len(data) - BLOCK_SIZE) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext must contain complete 8-byte blocks")

    expected_tag = hmac.new(mac_key, data, hashlib.sha256).digest()
    if not hmac.compare_digest(received_tag, expected_tag):
        raise ValueError("Authentication failed")

    iv = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    previous = iv
    plaintext = bytearray()

    for start in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[start:start + BLOCK_SIZE]
        decrypted = des.decrypt_block(int.from_bytes(block, "big"), des_key)
        original = decrypted ^ int.from_bytes(previous, "big")
        plaintext.extend(original.to_bytes(BLOCK_SIZE, "big"))
        previous = block

    padding = plaintext[-1]
    if not 1 <= padding <= BLOCK_SIZE:
        raise ValueError("Invalid padding")
    if plaintext[-padding:] != bytes([padding]) * padding:
        raise ValueError("Invalid padding")

    return plaintext[:-padding].decode("utf-8")
