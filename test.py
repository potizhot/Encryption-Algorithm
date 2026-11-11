from secrets import randbits
from statistics import median
from time import perf_counter
import des
import modified_des

# Encrypt a block and save the result after every round.
def encrypt_rounds(algorithm, plaintext, key):
    after_ip = algorithm.permute(plaintext, algorithm.IP, 64)
    left = after_ip >> 32
    right = after_ip & ((1 << 32) - 1)

    results = []

    for round_key in algorithm.make_round_keys(key):
        new_left = right
        new_right = left ^ algorithm.round_function(right, round_key)

        left = new_left
        right = new_right
        results.append((left << 32) | right)

    return results


tests = 3000
standard_totals = [0] * 16
modified_totals = [0] * 16

for _ in range(tests):
    plaintext = randbits(64)
    key = randbits(64)
    changed_plaintext = plaintext ^ (1 << randbits(6))

    # Give both DES versions the same plaintext, key, and flipped bit.
    for algorithm, totals in [
        (des, standard_totals),
        (modified_des, modified_totals),
    ]:
        original = encrypt_rounds(algorithm, plaintext, key)
        changed = encrypt_rounds(algorithm, changed_plaintext, key)

        for round_number in range(len(totals)):
            different_bits = original[round_number] ^ changed[round_number]
            totals[round_number] += different_bits.bit_count()


print(f"Average of {tests} one-bit-change tests:\n")

for name, totals in [
    ("Standard DES", standard_totals),
    ("Modified DES", modified_totals),
]:
    print(name)

    for round_number, total in enumerate(totals, start=1):
        percentage = total / tests / 64 * 100
        print(f"  Round {round_number}: {percentage:.2f}%")

    print()

# Test how often the final avalanche result is low.
key = 0x133457799BBCDFF1
tests = 3000
low_results = [0, 0]

for _ in range(tests):
    plaintext = randbits(64)
    changed = plaintext ^ (1 << randbits(6))

    for number, algorithm in enumerate([des, modified_des]):
        first = algorithm.encrypt_block(plaintext, key)
        second = algorithm.encrypt_block(changed, key)
        changed_bits = (first ^ second).bit_count()

        if changed_bits <= 25:  # 25 out of 64 is below 40%
            low_results[number] += 1

print(f"Standard DES below 40%: {low_results[0]} out of {tests}")
print(f"Modified DES below 40%: {low_results[1]} out of {tests}")

# Time both block ciphers with the same plaintexts and keys.
blocks = [(randbits(64), randbits(64)) for _ in range(300)]
for name, algorithm in [("Standard DES", des), ("Modified DES", modified_des)]:
    times = []
    for _ in range(3):
        start = perf_counter()
        for plaintext, key in blocks:
            algorithm.encrypt_block(plaintext, key)
        times.append((perf_counter() - start) / len(blocks) * 1000)
    print(f"{name} encryption: {median(times):.4f} ms/block")
