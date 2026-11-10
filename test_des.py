# tests for DES.py
from secrets import randbits
import DES as my_des

passed = 0
failed = 0


# show the result of one test
def show_result(name, ok):
    global passed, failed
    if ok:
        print("PASS -", name)
        passed = passed + 1
    else:
        print("FAIL -", name)
        failed = failed + 1


# Test 1: decrypting gives back the original message
message = "This is a secret message."
key = 0x133457799BBCDFF1
encrypted = my_des.encrypt_message(message, key)
decrypted = my_des.decrypt_message(encrypted, key)
show_result("Test 1: encrypt then decrypt gives the original", decrypted == message)

# Test 2: unmix_halves undoes mix_halves
if hasattr(my_des, "mix_halves") and hasattr(my_des, "unmix_halves"):
    left = randbits(32)
    right = randbits(32)
    mixed_left, mixed_right = my_des.mix_halves(left, right)
    back_left, back_right = my_des.unmix_halves(mixed_left, mixed_right)
    show_result("Test 2: unmix_halves undoes mix_halves", back_left == left and back_right == right)
else:
    show_result("Test 2: unmix_halves undoes mix_halves (functions not found)", False)

# Test 3: ciphertext is different from standard DES
# standard DES gives 85E813540F0AB405 for this message and key
ciphertext = my_des.encrypt_block(0x0123456789ABCDEF, 0x133457799BBCDFF1)
show_result("Test 3: ciphertext is different from standard DES", ciphertext != 0x85E813540F0AB405)



# encrypt and save the result after each round
def encrypt_rounds(plaintext, key):
    after_ip = my_des.permute(plaintext, my_des.IP, 64)
    left = after_ip >> 32
    right = after_ip & ((1 << 32) - 1)

    if hasattr(my_des, "mix_halves"):
        left, right = my_des.mix_halves(left, right)

    results = [(left << 32) | right]

    for round_key in my_des.make_round_keys(key):
        new_left = right
        new_right = left ^ my_des.round_function(right, round_key)
        left = new_left
        right = new_right
        results.append((left << 32) | right)

    return results


# change 1 bit in many random messages and get the average per round
tests = 3000
totals = [0] * 17

for test in range(tests):
    plain = randbits(64)
    test_key = randbits(64)
    changed = plain ^ (1 << randbits(6))

    rounds1 = encrypt_rounds(plain, test_key)
    rounds2 = encrypt_rounds(changed, test_key)

    for i in range(17):
        totals[i] = totals[i] + (rounds1[i] ^ rounds2[i]).bit_count()

round3 = totals[3] / tests / 64 * 100
round16 = totals[16] / tests / 64 * 100


# Test 4: average at round 16 is at least 49.5%
show_result(f"Test 4: round 16 average is {round16:.2f}%", round16 >= 49.5)


# Test 5: average at round 3 is at least 48%
show_result(f"Test 5: round 3 average is {round3:.2f}%", round3 >= 48)



# Test 6: the main test in DES.py changes only 1 bit
code = open("DES.py", encoding="utf-8").read()
show_result("Test 6: main test flips 1 bit of the first letter", "chr(ord(message[0]) ^ 1)" in code)


print()
print("Passed:", passed, "Failed:", failed)