import des

# example plaintext message
plaintext = 0x0123456789ABCDEF
# do initial permutation and split them in 2 halves 32 bits
after_ip = des.permute(plaintext, des.IP, 64)
l0 = after_ip >> 32
r0 = after_ip & ((1 << 32) - 1)

# example key
key = 0x133457799BBCDFF1
# permutated the key from 64bit to 56 bit then split it in 2
key_56 = des.permute(key, des.PC1, 64)
c0 = key_56 >> 28
d0 = key_56 & ((1 << 28) - 1)

c = c0
d = d0
round_keys = []

for shifts in des.KEY_SHIFTS:
    # left shift the split values, still 28bits, no bits dropped
    c = des.rotate_left_28(c, shifts)
    d = des.rotate_left_28(d, shifts)

    # permutated choice 2, join the two rotated 28 bits key, then permutate and choose 48 bits out of 56 bits
    joined_key = (c << 28) | d
    round_key = des.permute(joined_key, des.PC2, 56)
    round_keys.append(round_key)

# Run the 16 DES rounds
left = l0
right = r0

# loop for each round of des
for round_key in round_keys:
    f_result = des.round_function(right, round_key)

    # make the left half the new right and vice versa
    new_left = right
    new_right = left ^ f_result

    left = new_left
    right = new_right

# swap the halves, then apply the final permutation
before_fp = (right << 32) | left
ciphertext = des.permute(before_fp, des.FP, 64)

print(f"Ciphertext: {ciphertext:016X}")