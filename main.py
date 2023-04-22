import hashlib
import time
import random
import string
from collections import defaultdict


def md5_hash(txt):
    return hashlib.md5(txt.encode()).hexdigest()


def sha256_hash(txt):
    return hashlib.sha256(txt.encode()).hexdigest()


def sha3_hash(txt):
    return hashlib.sha3_256(txt.encode()).hexdigest()


def sha1_hash(txt):
    return hashlib.sha1(txt.encode()).hexdigest()


def blake2s_hash(txt):
    return hashlib.blake2s(txt.encode()).hexdigest()


def generate_random_string(length):
    return ''.join([random.choice(string.ascii_letters + string.digits) for _ in range(length)])


def measure_computation_time(hash_func, txt):
    start_time = time.time()
    hash_func(txt)
    end_time = time.time()
    return end_time - start_time


def check_for_collisions(hash_func, strings):
    hashes = {}
    collisions = 0
    for txt in strings:
        hash_val = hash_func(txt)
        if hash_val in hashes:
            collisions += 1
        else:
            hashes[hash_val] = txt
    return collisions


def main():
    strings = defaultdict(list)
    for i in range(10000):
        #length = random.randint(1, 10000)
        length = random.choice([1, 5, 10, 20, 30, 50, 100, 150])
        txt = generate_random_string(length)
        while txt in strings:
            txt = generate_random_string(length)

        strings[length].append(txt)

    hash_functions = [md5_hash, sha256_hash, sha3_hash, sha1_hash, blake2s_hash]

    with open('result.txt', 'w') as f:
        #for length in strings.keys():
        for length in [1, 5, 10, 20, 30, 50, 100, 150]:
            f.write(f"String length: {length}\n")
            for func in hash_functions:
                time_taken = []
                collisions = []
                for randomtext in strings[length]:
                    time_taken.append(measure_computation_time(func, randomtext))
                    collisions.append(check_for_collisions(func, strings[length]))
                f.write(
                    f"{func.__name__.upper()} - Time: {sum(time_taken):.4f} seconds, Collisions: {collisions[0]}\n")
            f.write('\n')
    f.close()


if __name__ == "__main__":
    main()
