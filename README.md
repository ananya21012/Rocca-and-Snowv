# Rocca-and-Snowv
# README: SNOW-V Implementation

This repository contains a basic implementation of the SNOW-V and Rocca stream cipher in python and a comparison of their performance for various input sizes of plaintext. Below are instructions for compiling and running the implementation.


# SNOWV
## Prerequisites
- Python 3.x

## Compilation
This is a Python implementation, so there is no need for traditional compilation. Just run snowv.py directly.


## Running the Implementation
To run the compiled binary with test inputs, use the following command:

```bash
./snowv < t1
```

Replace `t1` with the name of the desired test input file (e.g., `t2` or `t3`).

### Example:
```bash
./snowv < t2
```

## Input Format
The test input files (`t1`, `t2`, `t3`) should contain:
1. A 256-bit key, represented as a hexadecimal string.
2. A 128-bit IV (Initialization Vector), also represented as a hexadecimal string.

The program will process the input, initialize the SNOW-V cipher, and generate keystream blocks or encrypted data.

## Output
The program outputs the keystream or the result of encryption to the standard output, which can be redirected to a file if needed.

### Example:
```bash
./snow_v < t3 > output.txt
```

This will save the output to `output.txt`.

## Notes
- Ensure the input files are properly formatted with valid hexadecimal strings.
- For performance evaluation, the program outputs execution time in microseconds.

# ROCCA
## Prerequisites
- Python 3.x

## Compilation
This is a Python implementation, so there is no need for traditional compilation. Just run rocca.py directly.


## Running the Implementation
To run the python file rocca.py with test inputs, manually enter the nonce,key,associated data and plaintext.
Enter a pair of hex(byte) seperated by spaces.
To evaluate performance just run the rocca_time.py.

## Input Format
for rocca.py:
The test input files test_vectors should contain the following in a hexadecimal string:
1. A 256-bit key
2. A 128-bit nonce 
3. associated_data
4. plaintext

The program will process the input, initialize the rocca cipher, and generate encrypted data and tag.

for rocca_time.py:
The program will output the speed in Mbps for various input sizes of plaintext already specified in python file.

## Output
The program outputs the ciphertext and tag(for associated_data) to the standard output, which can be redirected to a file if needed.


## Notes
- Ensure the input files are properly formatted with valid hexadecimal strings(pairs of hex)
- For performance evaluation, the program outputs speed in Mbps.
