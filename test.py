"""Reproducible study of DES rotation-XOR diffusion. Run: python test.py."""

import csv
import platform
import random
import statistics
import sys
import time
from pathlib import Path

import des
import modified_des

# These candidates and targets are fixed before running the experiment.
OPTIONS = {
    "DES": (),
    "2 rotations": (1, 5),
    "4 rotations": (1, 5, 9, 13),
    "6 rotations": (1, 5, 9, 13, 17, 21),
    "8 rotations": (1, 5, 9, 13, 17, 21, 25, 29),
}
ROUND_3_TARGET = 48.0
WORST_BIT_TARGET = 45.0
RESULTS = Path(__file__).parent / "results"


def make_samples(seed, tests_per_bit):
    """Test each plaintext bit equally often, using repeatable random data."""
    rng = random.Random(seed)
    return [(rng.getrandbits(64), rng.getrandbits(64), bit)
            for bit in range(64) for _ in range(tests_per_bit)]


def encrypt_rounds(algorithm, plaintext, key):
    after_ip = algorithm.permute(plaintext, algorithm.IP, 64)
    left, right = after_ip >> 32, after_ip & 0xFFFFFFFF
    results = []

    for round_key in algorithm.make_round_keys(key):
        left, right = right, left ^ algorithm.round_function(right, round_key)
        results.append((left << 32) | right)

    return results


def measure_diffusion(algorithm, samples):
    round_totals = [0] * 16
    bit_totals = [0] * 64
    bit_tests = [0] * 64
    low_final = 0

    for plaintext, key, bit in samples:
        original = encrypt_rounds(algorithm, plaintext, key)
        changed = encrypt_rounds(algorithm, plaintext ^ (1 << bit), key)

        for index in range(16):
            changed_bits = (original[index] ^ changed[index]).bit_count()
            round_totals[index] += changed_bits
            if index == 2:
                bit_totals[bit] += changed_bits
                bit_tests[bit] += 1
            if index == 15 and changed_bits <= 25:
                low_final += 1

    rounds = [total / len(samples) / 64 * 100 for total in round_totals]
    bits = [bit_totals[bit] / bit_tests[bit] / 64 * 100 for bit in range(64)]
    return rounds, bits, low_final


def check_decryption(algorithm):
    rng = random.Random(20261112)
    for _ in range(100):
        plaintext, key = rng.getrandbits(64), rng.getrandbits(64)
        ciphertext = algorithm.encrypt_block(plaintext, key)
        if algorithm.decrypt_block(ciphertext, key) != plaintext:
            return False
    return True


def time_encryption(algorithm, samples):
    """Milliseconds per block, including the current key schedule."""
    blocks = [(plaintext, key) for plaintext, key, _ in samples[:1000]]
    measurements = []
    for _ in range(3):
        start = time.perf_counter()
        for plaintext, key in blocks:
            algorithm.encrypt_block(plaintext, key)
        measurements.append((time.perf_counter() - start) / len(blocks) * 1000)
    return statistics.median(measurements)


def save_csv(name, rows):
    with (RESULTS / name).open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def run_design(stage, name, samples, summary, round_rows, bit_rows):
    algorithm = des if name == "DES" else modified_des
    if algorithm is modified_des:
        modified_des.ROTATIONS = OPTIONS[name]

    rounds, bits, low_final = measure_diffusion(algorithm, samples)
    correct = check_decryption(algorithm)
    milliseconds = time_encryption(algorithm, samples)

    summary.append({
        "stage": stage, "design": name,
        "rotations": " ".join(map(str, OPTIONS[name])),
        "tests": len(samples), "round_3_percent": round(rounds[2], 3),
        "worst_bit_round_3_percent": round(min(bits), 3),
        "final_percent": round(rounds[15], 3),
        "final_below_40_count": low_final,
        "decrypts_correctly": correct,
        "milliseconds_per_block": round(milliseconds, 4),
    })
    for number, percentage in enumerate(rounds, 1):
        round_rows.append({"stage": stage, "design": name,
                        "round": number, "avalanche_percent": round(percentage, 3)})
    for bit, percentage in enumerate(bits):
        bit_rows.append({"stage": stage, "design": name,
                        "plaintext_bit": bit, "round_3_percent": round(percentage, 3)})

    print(f"{stage}: {name:11} | round 3 {rounds[2]:5.2f}% | "f"worst bit {min(bits):5.2f}% | {milliseconds:.4f} ms/block")


def main():
    RESULTS.mkdir(exist_ok=True)
    summary, round_rows, bit_rows = [], [], []
    training = make_samples(20261110, 100)  # 6,400 shared cases
    for name in OPTIONS:
        run_design("training", name, training, summary, round_rows, bit_rows)

    passing = [row for row in summary if row["design"] != "DES"
            and row["round_3_percent"] >= ROUND_3_TARGET
            and row["worst_bit_round_3_percent"] >= WORST_BIT_TARGET]
    selected = min(passing, key=lambda row: len(OPTIONS[row["design"]])) if passing else None

    if selected:
        print(f"Selected for fresh-data confirmation: {selected['design']}")
        designs_to_confirm = ("DES", selected["design"])
    else:
        print("No design met both training targets.")
        print("Checking 6 and 8 rotations on fresh data as exploratory results.")
        designs_to_confirm = ("DES", "6 rotations", "8 rotations")

    confirmation = make_samples(20261111, 200)  # 12,800 new cases
    for design in designs_to_confirm:
        run_design("confirmation", design, confirmation, summary, round_rows, bit_rows)

    save_csv("summary.csv", summary)
    save_csv("rounds.csv", round_rows)
    save_csv("input_bits.csv", bit_rows)
    settings = [
        {"setting": "training_seed", "value": 20261110},
        {"setting": "training_tests_per_input_bit", "value": 100},
        {"setting": "confirmation_seed", "value": 20261111},
        {"setting": "confirmation_tests_per_input_bit", "value": 200},
        {"setting": "round_3_target_percent", "value": ROUND_3_TARGET},
        {"setting": "worst_input_bit_target_percent", "value": WORST_BIT_TARGET},
        {"setting": "python_version", "value": sys.version.split()[0]},
        {"setting": "platform", "value": platform.platform()},
        {"setting": "timing_method", "value": "median of 3 runs; 1000 encrypt_block calls each; includes key schedule"},
    ]
    save_csv("settings.csv", settings)
    modified_des.ROTATIONS = OPTIONS["8 rotations"]
    print(f"Saved results in {RESULTS}")


if __name__ == "__main__":
    main()
