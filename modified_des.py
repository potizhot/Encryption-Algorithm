# function helpers
# show the bits 
def show_bits(value: int, width: int) -> str:
    """Show an integer as exactly `width` binary digits."""
    return f"{value:0{width}b}"

# encode message sa UTF-8 and pad it to complete 8-byte blocks
def prepare_message(message: str) -> bytes:
    if len(message) > 255:
        raise ValueError("Message must be at most 255 characters")

    message_bytes = message.encode("utf-8")

    padding_length = 8 - (len(message_bytes) % 8)
    padding = bytes([padding_length]) * padding_length

    return message_bytes + padding

# select and rearrange bits using different DES tables
def permute(value: int, table: list[int], input_width: int) -> int:
    result = 0

    for position in table:
        bit = (value >> (input_width - position)) & 1
        result = (result << 1) | bit

    return result

# rotation function, left shift(s)
def rotate_left_28(value: int, amount: int) -> int:
    mask = (1 << 28) - 1
    return ((value << amount) & mask) | (value >> (28 - amount))

# S-box lookup function, use the outside bits for the row, the middle bits for the column, and read the table
def use_s_box(group: int, box: list[list[int]]) -> int:
    bits = show_bits(group, 6)

    row_bits = bits[0] + bits[5]
    column_bits = bits[1:5]

    row = int(row_bits, 2)
    column = int(column_bits, 2)

    return box[row][column]

# CALCULATION USED EACH ROUND
# DES mangler function
def round_function(right: int, round_key: int) -> int:
    # expansion permutation for the right half of the plaintext
    expanded = permute(right, E, 32)
    # XOR the expanded right half with this round's key
    mixed = expanded ^ round_key

    # use function for S-box, send the first 6-bit group through all S-box to get 4 bits
    # Send each 6-bit group through its matching S-box
    s_boxes = [S1, S2, S3, S4, S5, S6, S7, S8]
    s_box_result = 0

    for group_number in range(8):
        shift = 42 - (group_number * 6)
        group = (mixed >> shift) & 0b111111

        four_bits = use_s_box(group, s_boxes[group_number])
        s_box_result = (s_box_result << 4) | four_bits

    # does the p permutation
    # Rearrange the S-box output using the standard P-box.
    p_result = permute(s_box_result, P, 32)

    # Make two rotated copies of those 32 bits.
    rotated_7 = ((p_result << 7) | (p_result >> 25)) & 0xFFFFFFFF
    rotated_19 = ((p_result << 19) | (p_result >> 13)) & 0xFFFFFFFF

    # Mix the original and both copies together.
    return p_result ^ rotated_7 ^ rotated_19


# DES tables
# initial permutation table list
IP = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
]

# permutated choice 1 table select 56 bits from the 64-bit key
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

# permutated choice 2: choose 48 bits from the joined key halves
PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

# Number of circular left shifts for rounds 1 through 16
KEY_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Expansion permutation select 48 bits from the 32-bit right message half
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
]

# S-box turns a 6-bit input into a 4-bit output
S1 = [
    [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
    [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
    [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
    [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
]

S2 = [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
]

S3 = [
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
]

S4 = [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
]

S5 = [
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
]

S6 = [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
]

S7 = [
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
]

S8 = [
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]

# P permutation: rearrange the 32 S-box output bits
P = [
    16,  7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25,
]

# final permutation or inverse initial permutation
FP = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
]

# OVERALL DES STEPS
# key handler
def make_round_keys(key: int) -> list[int]:
    # permutated the key from 64bit to 56 bit then split it in 2
    key_56 = permute(key, PC1, 64)
    c0 = key_56 >> 28
    d0 = key_56 & ((1 << 28) - 1)

    c = c0
    d = d0
    round_keys = []

    for shifts in KEY_SHIFTS:
        # left shift the split values, still 28bits, no bits dropped
        c = rotate_left_28(c, shifts)
        d = rotate_left_28(d, shifts)

        # permutated choice 2, join the two rotated 28 bits key, then permutate and choose 48 bits out of 56 bits
        joined_key = (c << 28) | d
        round_key = permute(joined_key, PC2, 56)
        round_keys.append(round_key)

    return round_keys

# encryption code
def encrypt_block(plaintext: int, key: int) -> int:
    # do initial permutation and split them in 2 halves 32 bits
    after_ip = permute(plaintext, IP, 64)
    l0 = after_ip >> 32
    r0 = after_ip & ((1 << 32) - 1)

    round_keys = make_round_keys(key)

    # Run the 16 DES rounds
    left = l0
    right = r0

    # loop for each round of des
    for round_key in round_keys:
        f_result = round_function(right, round_key)

        # make the left half the new right and vice versa
        new_left = right
        new_right = left ^ f_result

        left = new_left
        right = new_right

    # swap the halves, then apply the final permutation
    before_fp = (right << 32) | left
    ciphertext = permute(before_fp, FP, 64)
    return ciphertext

# decryption code
def decrypt_block(ciphertext: int, key: int) -> int:
    # initial permutation and split into two 32-bit halves
    after_ip = permute(ciphertext, IP, 64)
    left = after_ip >> 32
    right = after_ip & ((1 << 32) - 1)

    # decryption uses K16 first and K1 last
    round_keys = make_round_keys(key)

    for round_key in reversed(round_keys):
        f_result = round_function(right, round_key)

        new_left = right
        new_right = left ^ f_result

        left = new_left
        right = new_right

    # swap the halves and apply the inverse initial permutation
    before_fp = (right << 32) | left
    plaintext = permute(before_fp, FP, 64)

    return plaintext

# divide the encoded messages into 8 byte blocks and encrypt each block
def encrypt_message(message: str, key: int) -> bytes:
    prepared = prepare_message(message)
    encrypted = bytearray()

    for start in range(0, len(prepared), 8):
        block_bytes = prepared[start:start + 8]
        block_number = int.from_bytes(block_bytes, "big")

        encrypted_number = encrypt_block(block_number, key)
        encrypted.extend(encrypted_number.to_bytes(8, "big"))

    return bytes(encrypted)

# divide cipertext into 8 byte blocks and decrypt each block
def decrypt_message(ciphertext: bytes, key: int) -> str:
    if not ciphertext or len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext must contain complete 8-byte blocks")

    decrypted = bytearray()

    for start in range(0, len(ciphertext), 8):
        block_bytes = ciphertext[start:start + 8]
        block_number = int.from_bytes(block_bytes, "big")

        decrypted_number = decrypt_block(block_number, key)
        decrypted.extend(decrypted_number.to_bytes(8, "big"))

    padding_length = decrypted[-1]

    if not 1 <= padding_length <= 8:
        raise ValueError("Invalid padding")
    if decrypted[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Invalid padding")

    message_bytes = decrypted[:-padding_length]
    return message_bytes.decode("utf-8")

# avalanche effect testing, check across multiple bytes
def test_avalanche_effect(message: str, changed_message: str, key: int):

    original_bytes = message.encode("utf-8")
    modified_bytes = changed_message.encode("utf-8")

    # Ensure fair bit-by-bit comparison
    if len(original_bytes) != len(modified_bytes):
        raise ValueError(
            "Both messages must have the same byte length"
        )

    if original_bytes == modified_bytes:
        raise ValueError("The plaintext must be modified")

    # Encrypt both messages
    original = encrypt_message(message, key)
    changed = encrypt_message(changed_message, key)

    # Count changed plaintext bits
    plaintext_changed_bits = sum(
        (a ^ b).bit_count()
        for a, b in zip(original_bytes, modified_bytes)
    )

    # Find blocks containing modified plaintext bytes
    affected_blocks = {
        i // 8
        for i, (a, b) in enumerate(zip(original_bytes, modified_bytes))
        if a != b
    }

    # Compare all ciphertext bits
    ciphertext_changed_bits = sum(
        (a ^ b).bit_count()
        for a, b in zip(original, changed)
    )

    # Calculate avalanche in the affected blocks
    affected_bits = len(affected_blocks) * 64

    affected_avalanche = (
        ciphertext_changed_bits / affected_bits
    ) * 100

    # Calculate change across the entire ciphertext
    total_bits = len(original) * 8

    overall_change = (
        ciphertext_changed_bits / total_bits
    ) * 100

    return (
        plaintext_changed_bits,
        ciphertext_changed_bits,
        len(affected_blocks),
        affected_avalanche,
        overall_change
    )

# CHECKING THE CODE OUTPUTS
if __name__ == "__main__":
    print('THIS IS MODIFIED DES')
    message = input("Enter original plaintext: ")
    changed_message = input("Enter modified plaintext: ")

    key = 0x133457799BBCDFF1

    (
        input_bits,
        output_bits,
        affected_blocks,
        avalanche,
        overall
    ) = test_avalanche_effect(message, changed_message, key)

    print(f"\nOriginal Plaintext: {message}")
    print(f"Modified Plaintext: {changed_message}")

    print(f"\nPlaintext Bits Changed: {input_bits}")
    print(f"Ciphertext Bits Changed: {output_bits}")
    print(f"Affected DES Blocks: {affected_blocks}")
    print(f"Affected-Block Avalanche Effect: {avalanche:.2f}%")
    print(f"Whole-Message Ciphertext Change: {overall:.2f}%")