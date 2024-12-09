import time
from bitarray.util import int2ba, ba2int

# S-Box used in AES for the SubBytes step
sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

def hex_to_bin(c):
    return f"{int(c, 16):04b}"

def print_hex(arr):
    print(" ".join(f"{x:02x}" for x in arr))

def combine(a, b):
    return (a << 16) | b

def combine_16(a, b):
    return (a << 8) | b

def rotate_left(word, offset):
    return ((word << offset) | (word >> (32 - offset))) & 0xFFFFFFFF

def reduce(v, c):
    """Performs reduction in Galois Field."""
    if v & 0x8000:  # Check if the highest bit (15th) is set
        return ((v << 1) ^ c) & 0xFFFF  # Multiply by x and reduce modulo polynomial
    return (v << 1) & 0xFFFF  # Just multiply by x


def reduce_i(v, d):
    """Performs inverse reduction in Galois Field."""
    if v & 0x0001:  # Check if the least significant bit (LSB) is set
        return (v >> 1) ^ d  # Divide by x and adjust with polynomial
    return v >> 1  # Just divide by x


def lfsr(LFSR_A, LFSR_B):
    """Linear Feedback Shift Register (LFSR) logic."""
    for _ in range(8):  # Update for 8 cycles
        u = reduce(LFSR_A[0], 0x990F) ^ LFSR_A[1] ^ reduce_i(LFSR_A[8], 0xCC87) ^ LFSR_B[0]
        v = reduce(LFSR_B[0], 0xC963) ^ LFSR_B[3] ^ reduce_i(LFSR_B[8], 0xE4B1) ^ LFSR_A[0]

        for j in range(15):  # Shift all elements
            LFSR_A[j] = LFSR_A[j + 1]
            LFSR_B[j] = LFSR_B[j + 1]

        LFSR_A[15] = u  # New value at the end
        LFSR_B[15] = v  # New value at the end


def sigma(state):
    """Applies the sigma permutation."""
    s = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    tmp = [0] * 16
    for i in range(16):
        tmp[i] = (state[s[i] >> 2] >> ((s[i] & 3) * 8)) & 0xFF

    for i in range(4):
        state[i] = combine(combine_16(tmp[4 * i + 3], tmp[4 * i + 2]),
                           combine_16(tmp[4 * i + 1], tmp[4 * i]))


def aes_round(result, state, round_key):
    """AES encryption round."""
    sb = [0] * 16  # Temporary array for SubBytes results

    # Populate the sb array with the SubBytes transformation
    for i in range(4):
        for j in range(4):
            sb[i * 4 + j] = sbox[(state[i] >> (j * 8)) & 0xFF]

    # Define the MixColumns step
    def mixcol(j):
        nonlocal sb
        w = (sb[(j * 4 + 0) % 16] << 24) | (sb[(j * 4 + 5) % 16] << 0) | \
            (sb[(j * 4 + 10) % 16] << 8) | (sb[(j * 4 + 15) % 16] << 16)

        t = rotate_left(w, 16) ^ ((w << 1) & 0xFEFEFEFE) ^ \
            (((w >> 7) & 0x01010101) * 0x1B)

        # AddRoundKey: XOR with the round key
        result[j] = round_key[j] ^ w ^ t ^ rotate_left(t, 8)

    # Perform the round transformations for all columns
    for j in range(4):
        mixcol(j)


def fsm(LFSR_A, LFSR_B, R1, R2, R3):
    """Finite State Machine (FSM) logic."""
    C1 = [0] * 4
    C2 = [0] * 4
    R1_copy = R1[:]

    for i in range(4):
        T2 = combine(LFSR_A[2 * i + 1], LFSR_A[2 * i])
        R1[i] = (T2 ^ R3[i]) + R2[i]

    sigma(R1)
    aes_round(R3, R2, C2)
    aes_round(R2, R1_copy, C1)


def keystream(z, LFSR_A, LFSR_B, R1, R2, R3):
    """Generates keystream."""
    for i in range(4):
        T1 = combine(LFSR_B[2 * i + 9], LFSR_B[2 * i + 8])
        v = (T1 + R1[i]) ^ R2[i]
        z[i * 4 + 0] = (v >> 0) & 0xFF
        z[i * 4 + 1] = (v >> 8) & 0xFF
        z[i * 4 + 2] = (v >> 16) & 0xFF
        z[i * 4 + 3] = (v >> 24) & 0xFF

    fsm(LFSR_A, LFSR_B, R1, R2, R3)
    lfsr(LFSR_A, LFSR_B)

def init(key, iv, LFSR_A, LFSR_B, R1, R2, R3):
    for i in range(8):
        LFSR_A[i] = combine_16(iv[2 * i + 1], iv[2 * i])
        LFSR_A[i + 8] = combine_16(key[2 * i + 1], key[2 * i])
        LFSR_B[i] = 0x0000
        LFSR_B[i + 8] = combine_16(key[2 * i + 17], key[2 * i + 16])

    for i in range(4):
        R1[i] = R2[i] = R3[i] = 0x00000000

    for _ in range(16):
        z = [0] * 16
        keystream(z, LFSR_A, LFSR_B, R1, R2, R3)
        print_hex(z)
        for j in range(8):
            LFSR_A[j + 8] ^= combine_16(z[2 * j + 1], z[2 * j])

        if _ == 14:
            for j in range(4):
                R1[j] ^= combine(
                    combine_16(key[4 * j + 3], key[4 * j + 2]),
                    combine_16(key[4 * j + 1], key[4 * j + 0])
                )
        elif _ == 15:
            for j in range(4):
                R1[j] ^= combine(
                    combine_16(key[4 * j + 19], key[4 * j + 18]),
                    combine_16(key[4 * j + 17], key[4 * j + 16])
                )

def main():
    LFSR_A = [0] * 16
    LFSR_B = [0] * 16
    R1 = [0] * 4
    R2 = [0] * 4
    R3 = [0] * 4

    key = [0] * 32
    iv = [0] * 16
    key_str = input("Enter 256-bit key: \n")
    iv_str = input("Enter 128-bit IV: \n")

    idx = 0
    for i in range(0, len(key_str), 2):
        key[idx] = int(key_str[i:i + 2], 16)
        idx += 1
    idx = 0;
    for i in range(0, len(iv_str), 2):
        iv[idx] = int(iv_str[i:i + 2], 16)
        idx += 1

    print("Key =")
    print_hex(key)
    print("IV =")
    # print_hex(iv)

    plaintext = [[1] * 16 for _ in range(1)]
    start = time.time()
    print("Initialization phase, z =")
    init(key, iv, LFSR_A, LFSR_B, R1, R2, R3)
    print("Keystream phase, z =")

    for block in plaintext:
        z = [0] * 16
        keystream(z, LFSR_A, LFSR_B, R1, R2, R3)
        print_hex(z)
        for j in range(16):
            block[j] ^= z[j]

    end = time.time()
    print(f"Duration: {int((end - start) * 1e6)} microseconds")

    for block in plaintext:
        print_hex(block)

if __name__ == "__main__":
    main()

