# Copyright Xenigma 2024- (C) All Rights Reserved

import struct

def Rotate_Left(value, shift):
    return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))

def CRIS5(message):
    # Initialize variables
    a = 0x67452301
    b = 0xEFCDAB89
    c = 0x98BADCFE
    d = 0x10325476

    # Padding
    original_length = len(message)
    message += b'\x80'
    while (len(message) % 64) != 56:
        message += b'\x00'
    message += struct.pack('<Q', original_length * 8)

    # Process the message in 512-bit blocks
    for i in range(0, len(message), 64):
        chunk = message[i:i+64]
        words = list(struct.unpack('<16I', chunk))

        aa, bb, cc, dd = a, b, c, d

        # Round 1
        for i in range(16):
            F = (bb & cc) | ((~bb) & dd)
            g = i
            index = g
            a = b + Rotate_Left((a + F + words[g] + 0xD76AA478) & 0xFFFFFFFF, 7)
            d, c, b = c, Rotate_Left(b, 10), c
            b, a, d = a, b, d
            a, b, c, d = d, a, b, c

        # Round 2
        for i in range(16):
            F = (b & c) | ((~c) & d)
            g = (5*i + 1) % 16
            index = (1 * g + 5 * (g//4)) % 16
            a = b + Rotate_Left((a + F + words[index] + 0xE8C7B756) & 0xFFFFFFFF, 12)
            d, c, b = c, Rotate_Left(b, 10), c
            b, a, d = a, b, d
            a, b, c, d = d, a, b, c

        # Round 3
        for i in range(16):
            F = b ^ c ^ d
            g = (3**i + 5) % 16
            index = (5 * g + 1) % 16
            a = b + Rotate_Left((a + F + words[index] + 0x242070DB) & 0xFFFFFFFF, 17)
            d, c, b = c, Rotate_Left(b, 10), c
            b, a, d = a, b, d
            a, b, c, d = d, a, b, c

        # Round 4
        for i in range(16):
            F = c ^ (b | (~d))
            g = (7*i) % 16
            index = (3 * g + 7) % 16
            a = b + Rotate_Left((a + F + words[index] + 0xC1BDCEEE) & 0xFFFFFFFF, 22)
            d, c, b = c, Rotate_Left(b, 10), c
            b, a, d = a, b, d
            a, b, c, d = d, a, b, c

        # Update variables
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF

    # Convert the final hash to hexadecimal
    result = ''.join(format(x, '08x') for x in (a, b, c, d))

    return result
