from challenge21 import MT19937
from random import randint
from time import time

current_time = int(time())


def routine():
    global current_time
    current_time += randint(40, 1000)

    seed = current_time
    rng = MT19937(seed)

    current_time += randint(40, 1000)
    return seed, rng.extract_number()


def crack_mt19937_seed(rng_output):
    """
    try the most recent timestamps as seeds until the
    first output of the newly created MT19937 matches rng_output.
    """
    global current_time

    guessed_seed = current_time + 1
    rng = MT19937(guessed_seed)

    # Decrease the timestamp by 1 every time until we find the same output
    while rng.extract_number() != rng_output:
        guessed_seed -= 1
        rng = MT19937(guessed_seed)

    return guessed_seed


if __name__ == '__main__':
    real_seed, rng_output = routine()
    print(rng_output)
    print(real_seed)
    print(real_seed == crack_mt19937_seed(rng_output))