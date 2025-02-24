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

def guess_padding():
        

    default_url = "http://localhost:8080"

    cipher_url = f"{default_url}/eavesdrop"

    cipher_sample = requests.get(cipher_url)
    session = requests.Session()
    if cipher_sample.status_code == 200:
        soup = BeautifulSoup(cipher_sample.text, "html.parser")
        stuff = soup.find_all("p")[1].get_text().strip()
        print('\nCipher text:\n\n' + stuff + '\n')

        cipher_bytes = bytes.fromhex(stuff)
        cipher_blocks = [cipher_bytes[i:i + 16] for i in range(0, len(cipher_bytes), 16)]

        final_message = []
        # Iterate through all the blocks, starting at the second to last one
        for i in range(len(cipher_blocks) - 2, 0, -1):
            final_block = []
            block = bytearray(cipher_blocks[i])
            print(bytes([block[0]]))
            print("hi")
            padding = 0
            # Iterate through each byte of the block
            for j in range(len(block) - 1, 0, -1):
                padding += 1
                print(len(block))
                # Try all possible bytes
                for k in range(255):
                    block[j] ^= k
                    for l in range(len(block) - 1, len(block) - 1 - padding, -1):
                        block[j] ^= padding
                    
                    
                    cipher_blocks[i] = bytes(block)

                    modified_cookie = b"".join(cipher_blocks)
                    
                    modified_cookie_hex = modified_cookie.hex()
                    print(modified_cookie_hex)
                    
                    guess = session.get(f"{default_url}/?enc={modified_cookie_hex}")
                    if (guess.status_code == 404):
                        final_block.append(k)
            final_message.append(final_block)
        return final_message
                        
            

    else:
        print("bad request")


this = guess_padding()
yes = bytes(this[0])
hexstr = yes.hex()
print("\n")
print(hexstr)

    # for block in blocks:
    #     block_arr = bytearray(block)

    #     for byte in block_arr:

    #         for char in range(255):
    #             print("hi")
