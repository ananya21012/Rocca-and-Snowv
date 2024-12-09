import time
from rocca import rocca_encrypt

# Test parameters
plaintext_sizes_in_bits = [128, 256, 1024, 8192, 81920]  # List of plaintext sizes in bits

# Key setup (AES-128, split into two 16-byte parts)
key = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
key_values = key.split()
key_in_integers = [int(value, 16) for value in key_values]
key_part_0, key_part_1 = key_in_integers[:16], key_in_integers[16:]

# Nonce setup
nonce = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
nonce_values = nonce.split()
nonce_in_integers = [int(value, 16) for value in nonce_values]

# Associated data setup
associated_data = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
associated_data_values = associated_data.split()
associated_data_in_integers = [int(value, 16) for value in associated_data_values]

# Initial state for Rocca encryption (this could be modified as needed)
state = [0] * 8

# Helper function to generate plaintext of a given size
def generate_plaintext(size_in_bits):
    """
    Generates a plaintext message filled with zero bytes of the requested size in bits.
    """
    size_in_bytes = size_in_bits // 8  # Convert bits to bytes
    return "00 " * size_in_bytes  # Return a string of zero bytes

# Measure encryption time for each plaintext size
for plaintext_size in plaintext_sizes_in_bits:
    # Generate the message based on the current size
    message = generate_plaintext(plaintext_size)
    
    # Convert message from hexadecimal string to a list of integers
    message_values = message.split()
    message_in_integers = [int(value, 16) for value in message_values]
    
    # Record the start time for encryption
    start_time = time.perf_counter()
    
    # Perform Rocca encryption
    cipher, tag = rocca_encrypt(key_part_0, key_part_1, nonce_in_integers, associated_data_in_integers, message_in_integers, state)
    
    # Record the end time
    end_time = time.perf_counter()
    
    # Calculate the elapsed time and speed in Mbps
    elapsed_time = end_time - start_time
    encryption_speed = plaintext_size / elapsed_time  # Speed in bits per second
    encryption_speed_Mbps = encryption_speed / (10**6)  # Convert to Mbps
    
    # Print the encryption speed for the current plaintext size
    print(f"Plaintext size: {plaintext_size} bits, Encryption speed: {encryption_speed_Mbps:.6f} Mbps")
