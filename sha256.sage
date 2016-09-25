'''
A SAGE implementation of SHA256
Author: Josephine Garces
'''

import hashlib
from sage.crypto.util import ascii_integer

TRUNCATE_CONST = 0xFFFFFFFF

def main():

    sha256("manoa")
    sha256("abc")


# ror function from http://stackoverflow.com/a/27229191/2508324
def ror(val, r_bits):
    return ((val >> r_bits) | (val << (32-r_bits))) & TRUNCATE_CONST


# because sage doesn't like python syntax
def xor(a, b):
    return eval("%s^%s"%(a,b))


def sha256(data_str):
    bin = BinaryStrings()
    msg = str(bin.encoding(data_str))

    #Initialize hash values:
    #(first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

    #Initialize array of round constants:
    #(first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
    k = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    pre_data = pre_processing(msg)
    chunks = create_chunks(pre_data)
    process_to_chunks(chunks, k, h, data_str)


def pre_processing(message):

    # append the bit '1' to the message
    pre_message = str(message) + "1"

    # append k bits '0', where k is the minimum number... so on
    while len(pre_message) % 512 != 448:
        pre_message += '0'

    # append length of message (without the '1' bit or padding), in bits, as 64-bit big-endian integer
    # (this will make the entire post-processed length a multiple of 512 bits)
    pre_processed = pre_message + "{:064b}".format(len(message)).zfill(64)
    return pre_processed


def create_chunks(message):
    bin_array = []
    # Process the message in successive 512-bit chunks:
    for n in range(0, len(message), 512):
        bin_array.append(message[n:n+512])
    return bin_array


def process_to_chunks(chunks, k, hex_values, data):
    digest = ""

    for i in range(len(chunks)):
        # create a 64-entry message schedule array w[0..63] of 32-bit words
        w = [0 for _ in range(64)]

        # copy chunk into first 16 words w[0..15] of the message schedule array
        for j in range(16):
            w[j] = int(''.join(str(x) for x in chunks[i][32*j:32*(j+1)]), 2)

        # extend the first 16 words into the remaining 48 words w[16..63]
        for j in range(16, 64):
            s0 = xor(xor(ror(w[j-15], 7), ror(w[j-15], 18)), (w[j-15] >> 3))
            s1 = xor(xor(ror(w[j-2], 17), ror(w[j-2], 19)), (w[j-2] >> 10))
            w[j] = (w[j-16] + s0 + w[j-7] + s1) & TRUNCATE_CONST

        # Initialize working variables to current hash value:
        a, b, c, d, e, f, g, h = hex_values

        # Compression function main loop:
        for j in range(64):
            s1 = xor(xor(ror(e, 6), ror(e, 11)), ror(e, 25))
            ch = xor((e & f), (~int(e) & g))
            temp1 = (h + s1 + ch + k[j] + w[j]) & TRUNCATE_CONST
            s0 = xor(xor(ror(a, 2), ror(a, 13)), ror(a, 22))
            maj = xor(xor((a & b), (a & c)), (b & c))
            temp2 = s0 + maj & TRUNCATE_CONST

            # Add the compressed chunk to the current hash value:
            h = g
            g = f
            f = e
            e = (d + temp1) & TRUNCATE_CONST
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & TRUNCATE_CONST

        # Produce the final hash value (big-endian):
        digest = [(hex_value+alphabet) & TRUNCATE_CONST for hex_value, alphabet in zip(hex_values, [a, b, c, d, e, f, g, h])]

    print "Real: " + hashlib.sha256(data).hexdigest()
    print "Code: " + ''.join('{:08x}'.format(item) for item in digest)

main()
