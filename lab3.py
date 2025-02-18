import base64
import binascii
import datetime
import time
import random
import requests

from bs4 import BeautifulSoup
from Crypto.Cipher import AES


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))



# Task 1 - Padding Oracle

# You want to guess the last byte, lets say you guess 'g' and 
# xor that byte (previous cipher block) with 'g', if you are right you
# will make that bit 0x00, and from there you can xor it with 0x01 to
# test if the padding is 1, then you can make that 0x02 and so on
# it's brute force so for each byte, you try each letter and each padding

default_url = "http://localhost:8080"

cipher_url = f"{default_url}/eavesdrop"

cipher_sample = requests.get(cipher_url)

if cipher_sample.status_code == 200:
    soup = BeautifulSoup(cipher_sample.text, "html.parser")
    stuff = soup.find_all("p")[1].get_text().strip()
    print('\nCipher text:\n\n' + stuff + '\n')

    cipher_bytes = bytes.fromhex(stuff)
    cipher_blocks = [cipher_bytes[i:i + 16] for i in range(0, len(cipher_bytes), 16)]


    # Iterate through all the blocks, starting at the second to last one
    for i in range(len(cipher_blocks) - 2, 0, -1):
    
        block = bytearray(cipher_blocks[i])

        # Iterate through each byte of the block
        for j in range(len(block) - 1, 0, -1):

            # Try all possible bytes
            for k in range(255):

                # Test all possible paddings
                for l in range(15):

                    # Apply the padding to the block
                    for m in range(len(block) - 1, l, -1):
                        block[m] ^= bytes([l])

else:
    print("bad request")

# for block in blocks:
#     block_arr = bytearray(block)

#     for byte in block_arr:

#         for char in range(255):
#             print("hi")
