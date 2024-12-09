import numpy as np

# Main function to perform Rocca-S encryption
def rocca_encrypt(key0, key1, nonce, associated_data, plaintext, initial_state):
    """
    Encrypts the input message using Rocca encryption algorithm.

    Args:
        key0, key1: 128-bit keys for encryption.
        nonce: 128-bit unique value (used once).
        associated_data: Data to be authenticated but not encrypted.
        plaintext: The message to be encrypted.
        initial_state: Initial state for the encryption process.

    Returns:
        tuple: Encrypted ciphertext and authentication tag.
    """
    # Initialize the state with keys and nonce
    state = initialize_state(nonce, key0, key1, initial_state)

    # Prepare and pad the input data
    associated_data_length = len(associated_data)
    message_length = len(plaintext)
    padded_associated_data = pad_to_block_size(associated_data)
    padded_message = pad_to_block_size(plaintext)

    # Process associated data
    if associated_data_length > 0:
        state = process_associated_data(state, padded_associated_data)

    # Encrypt the message
    ciphertext = []
    if message_length > 0:
        ciphertext = [0] * len(padded_message)
        ciphertext, state = encrypt_message(state, padded_message, ciphertext)
        # Truncate to original message length
        ciphertext = ciphertext[:message_length]

    # Encode metadata for tag generation
    encoded_ad_len = encode_length_as_little_endian(associated_data_length * 8)
    encoded_msg_len = encode_length_as_little_endian(message_length * 8)

    # Generate the authentication tag
    tag = finalize_state(state, encoded_ad_len, encoded_msg_len)
    
    return ciphertext, tag

# Helper function to pad data to 32-byte block size
def pad_to_block_size(data):
    """
    Pads the data to a 32-byte block size with zeros.

    Args:
        data: List of integers (bytes).

    Returns:
        List of integers padded to the nearest 32-byte boundary.
    """
    padding_length = (32 - len(data) % 32) % 32
    return data + [0x00] * padding_length

# Updates the state using a single round of transformations
def update_round_state(state, input_block0, input_block1):
    """
    Updates the state using input blocks and AES encryption.

    Args:
        state: Current state of the cipher (list of 8 blocks).
        input_block0, input_block1: 16-byte input blocks.

    Returns:
        Updated state after applying transformations.
    """
    updated_state = [0] * 8
    updated_state[0] = xor_blocks(state[7], input_block0)
    updated_state[1] = aes_encrypt(state[0], state[7])
    updated_state[2] = xor_blocks(state[1], state[6])
    updated_state[3] = aes_encrypt(state[2], state[1])
    updated_state[4] = xor_blocks(state[3], input_block1)
    updated_state[5] = aes_encrypt(state[4], state[3])
    updated_state[6] = aes_encrypt(state[5], state[4])
    updated_state[7] = xor_blocks(state[0], state[6])
    return updated_state

# XOR operation for two blocks
def xor_blocks(block1, block2):
    """
    Computes the XOR of two byte blocks.

    Args:
        block1, block2: Lists of bytes to XOR.

    Returns:
        List of XORed bytes.
    """
    return [b1 ^ b2 for b1, b2 in zip(block1, block2)]

# Initialization phase of Rocca-S
def initialize_state(nonce, key0, key1, state):
    """
    Initializes the state using nonce, keys, and fixed constants.

    Args:
        nonce: 128-bit unique value.
        key0, key1: Encryption keys.
        state: Initial state array to be configured.

    Returns:
        Initialized state.
    """
    # Fixed constants (z0 and z1)
    z0 = "428a2f98d728ae227137449123ef65cd"
    z1 = "b5c0fbcfec4d3b2fe9b5dba58189dbbc"

    #little endian bytes list
    z0_bytes = [int(z0[i:i+2], 16) for i in range(0, len(z0), 2)][::-1]
    z1_bytes = [int(z1[i:i+2], 16) for i in range(0, len(z1), 2)][::-1]

    # Configure the state with keys, nonce, and constants
    state[0:4] = [key1, nonce, z0_bytes, z1_bytes]
    state[4:8] = [xor_blocks(nonce, key1), [0x00] * 16, key0, [0x00] * 16]

    # Apply 20 rounds of state transformation
    for _ in range(20):
        state = update_round_state(state, z0_bytes, z1_bytes)
    
    return state

# Processes the associated data for encryption
def process_associated_data(state, associated_data):
    """
    Processes associated data by updating the state for each block.

    Args:
        state: Current cipher state.
        associated_data: Padded associated data to be processed.

    Returns:
        Updated state after processing associated data.
    """
    num_blocks = len(associated_data) // 32
    for i in range(num_blocks):
        ad_block = associated_data[i*32:(i+1)*32]
        state = update_round_state(state, ad_block[:16], ad_block[16:])
    return state

# Encrypts the plaintext message
def encrypt_message(state, plaintext, ciphertext):
    """
    Encrypts the plaintext message block-by-block.

    Args:
        state: Current state of the cipher.
        plaintext: Padded plaintext to be encrypted.
        ciphertext: Pre-allocated ciphertext list to store results.

    Returns:
        Tuple of updated ciphertext and final state.
    """
    num_blocks = len(plaintext) // 32
    for i in range(num_blocks):
        msg_block = plaintext[i*32:(i+1)*32]
        ciphertext[i*32:i*32+16] = xor_blocks(aes_encrypt(state[1], state[5]), msg_block[:16])
        ciphertext[i*32+16:i*32+32] = xor_blocks(aes_encrypt(xor_blocks(state[0], state[4]), state[2]), msg_block[16:])
        state = update_round_state(state, msg_block[:16], msg_block[16:])
    return ciphertext, state

# Finalizes the encryption process to compute the authentication tag
def finalize_state(state, encoded_ad_len, encoded_msg_len):
    """
    Finalizes the state to produce an authentication tag.

    Args:
        state: Final state of the cipher after processing data.
        encoded_ad_len, encoded_msg_len: Encoded lengths of associated data and message.

    Returns:
        Authentication tag as a list of bytes.
    """
    for _ in range(20):
        state = update_round_state(state, encoded_ad_len, encoded_msg_len)

    tag = [0x00] * 16
    for block in state:
        tag = xor_blocks(tag, block)
    return tag

# Encodes a length as a 32-byte little-endian value
def encode_length_as_little_endian(length):
    """
    Encodes an integer length into a 32-byte little-endian representation.

    Args:
        length: Length value to encode.

    Returns:
        Encoded length as a list of bytes.
    """
    hex_rep = hex(length)[2:]
    padded_hex = hex_rep.zfill(32)
    byte_list = [int(padded_hex[i:i+2], 16) for i in range(0, len(padded_hex), 2)]
    return byte_list[::-1]


def get_input(input_name):
    """
    Prompts the user to enter 16 pairs of hexadecimal values, 
    splits the input into individual values and converts each byte to an integer.
    """
    print(f"Enter 16 hex values for {input_name}: ")
    # Read the input as a space-separated string and convert it to a list of bytes
    input_values = input().split()
    # Convert each input hex byte to an integer (base 16)
    return [int(value, 16) for value in input_values]


# AES S-box (substitution box)
s_box = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]

def substitute_bytes(state):
    """
    Substitute each byte in the state matrix using the AES S-box.
    """
    for i in range(4):
        for j in range(4):
            byte = state[i][j]  # Get the current byte
            row = (byte >> 4) & 0x0F  # Higher 4 bits
            col = byte & 0x0F  # Lower 4 bits
            # Substitute using the S-box
            state[i][j] = s_box[row][col]
    return state


def shift_rows(state):
    """
    Shift rows of the state matrix. 
    The 1st row is left unchanged, the 2nd row is shifted by 1,
    the 3rd row by 2, and the 4th row by 3.
    """
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state


def xtime(byte):
    """
    Perform the xtime operation used in MixColumns.
    If the highest bit is set, apply the AES irreducible polynomial (0x1B).
    """
    return ((byte << 1) ^ 0x1B) & 0xFF if (byte & 0x80) else (byte << 1)


def mix_single_column(column):
    """
    Apply the MixColumns transformation to a single column of the state.
    """
    t = column[0] ^ column[1] ^ column[2] ^ column[3]
    temp0 = column[0]
    column[0] ^= xtime(column[0] ^ column[1]) ^ t
    column[1] ^= xtime(column[1] ^ column[2]) ^ t
    column[2] ^= xtime(column[2] ^ column[3]) ^ t
    column[3] ^= xtime(column[3] ^ temp0) ^ t
    return column


def mix_columns(state):
    """
    Apply the MixColumns transformation to the entire state (column-wise).
    """
    for i in range(4):  # Iterate over each column
        col = [state[0][i], state[1][i], state[2][i], state[3][i]]
        mixed_column = mix_single_column(col)
        for j in range(4):
            state[j][i] = mixed_column[j]
    return state


def add_round_key(state, round_key):
    """
    XOR the state with the round key.
    """
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state


def transpose_matrix(matrix):
    """
    Transpose a matrix
    """
    return [list(row) for row in zip(*matrix)]

def print_state(state):
    """
    Print the state matrix in a readable format.
    """
    for row in state:
        print(" ".join(f"{byte:02X}" for byte in row))
    print()


# AES-128 encryption function
def aes_encrypt(plaintext, key):
    """
    AES-128 encryption function that processes a 16-byte plaintext and a 16-byte key.
    It applies the AES encryption steps including SubBytes, ShiftRows, and MixColumns.
    """

    # Convert the plaintext and key into a 4x4 matrix (transpose of the matrix)
    state = [list(plaintext[i:i + 4]) for i in range(0, 16, 4)]
    key1 = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    
    # Transpose the matrices
    state = transpose_matrix(state)
    key1 = transpose_matrix(key1)

    # Perform the AES transformations on the state
    state = substitute_bytes(state)
    state = shift_rows(state)
    state = mix_columns(state)

    # Transpose the matrices back
    state = transpose_matrix(state)
    key1 = transpose_matrix(key1)
    
    # Flatten the state and key matrices to 1D arrays
    state = [byte for row in state for byte in row]
    key1 = [byte for row in key1 for byte in row]

    # XOR the flattened state with the key
    return xor_blocks(state, key1)

    
 
def main():
    """
    Main function to call rocca_encrypt 
    It handles input for nonce, key, associated data, and message, 
    then performs encryption and prints the ciphertext and tag.
    """
    
    # Initialize an empty state
    state = [0] * 8

    # Get inputs from the user for nonce, key, associated data, and message
    nonce = get_input("nonce")
    key = get_input("key")
    
    # Split the key into two 16-byte parts
    key0, key1 = key[:16], key[16:]
    
    print("Key part 0:", key0)
    print("Key part 1:", key1)
    
    # Get associated data and message from the user
    associated_data = get_input("associated_data")
    message = get_input("message")

    # Perform encryption using the Rocca cipher
    cipher, tag = rocca_encrypt(key0, key1, nonce, associated_data, message, state)
    
    # Convert cipher and tag into 4x4 matrices for easy display
    cipher_matrix = [list(cipher[i:i + 4]) for i in range(0, len(cipher), 4)]
    tag_matrix = [list(tag[i:i + 4]) for i in range(0, len(tag), 4)]

    # Print the results in a readable format
    print("Ciphertext:")
    print_state(cipher_matrix)
    print("Tag:")
    print_state(tag_matrix)



if __name__ == "__main__":
    main()



