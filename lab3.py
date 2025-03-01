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


default_urls = ["http://localhost:8080", "http://0.0.0.0:8080"]
def check_url(urls):
    for url in urls:
        try: 
            requests.get(url).status_code
        except:
            # one URL will be valid, the other won't
            pass
        else:
            return url

default_url = check_url(default_urls)
cipher_url = f"{default_url}/eavesdrop"
def guess_padding():
    counterr = 0
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

        for i in range(len(cipher_blocks)):
            block_block = []
            if i == len(cipher_blocks) - 2:
                # special case with last one
                print("hi")
            else:

                cur_block = bytearray(cipher_blocks[i])
                next_block = bytearray(cipher_blocks[i + 1])
                padding = 0
                final_block = []
                # block = bytearray(cipher_blocks[i])

                # Iterate through each byte of the block
                for j in range(len(cur_block) - 1, -1, -1):
                    padding += 1

                    # Try all possible bytes
                    for k in range(255):
                        cur_block[j] ^= k
                        for l in range(len(cur_block) - 1, len(cur_block) - 1 - padding - 1, -1):
                            cur_block[l] ^= padding
                        

                        # cipher_blocks[i] = bytes(cur_block)
                        final_block.append(bytes(cur_block))
                        final_block.append(bytes(next_block))

                        modified_cookie = b"".join(final_block)
                        
                        modified_cookie_hex = modified_cookie.hex()

                        
                        guess = session.get(f"{default_url}/?enc={modified_cookie_hex}")
                        if (guess.status_code == 404):
                            break
                            # block_block.append(k)
                

                final_message.append(cur_block)
        




        return final_message
                        
            

    else:
        print("bad request")


"""ll = [1, 2, 3 ,4]
print(len(ll))
for i in range(len(ll)):
    print(i)




this = guess_padding()
print("\n")
print(this)
print("\n")
print(len(this))
yes = bytes(this[0])
print(yes)
print("\n")
print("AAAAAAAHHHHHHHHHHHH")
hexstr = yes.hex()
print("\n")
print(hexstr)"""

    # for block in blocks:
    #     block_arr = bytearray(block)

#     for byte in block_arr:

# SHA1

# SHA1 helpers
def left_rotate(val, count):
    char_bit = 8    # num bits in a char
    u_mask = (char_bit * len(str(val)) - 1) & 0xFFFFFFFF   # the hex makes unsigned
    count &= u_mask
    return ((val) << count | (val >> (-count & u_mask)))

# SHA1 function
def sha1(msg):
    # 1. initialize variables
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    bin_msg = bin(int.from_bytes(msg, byteorder="big"))[2:]  # remove '0b' prefix
    msg_len = len(bin_msg)

    # 2. pre-processing
    # append the bit '1' to the message
    # then append 0 ≤ k < 512 bits of '0' s.t. the ml is congruent to
    # -64 ≡ 448 (mod 512) (len % 512 = 448)
    # then append ml (orig. len) as a 64-bit big-endian int
    # .: total len is multiple of 512 bits

    bin_msg += str(0b1) # ???????? not sure what the multiple thing was
    count = 0
    while ((not (len(bin_msg) % 512) == 448) or count == 512):
        bin_msg += str(0b0)  # ???????
    bin_msg += str(msg_len)

    # 3. process message in 512-bit chunks
    # for each chunk:
    #   break each chunk into 16 32-bit big-endian words w[i], 0 ≤ i ≤ 15
    #   for i from 16 to 79:
    #       w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor 1[i-16]) leftrotate 1
    #       leftrotate: https://en.wikipedia.org/wiki/Circular_shift

    #   initialize hash value

    msg_list = [bin_msg[i:i + 512] for i in range(0, msg_len, 512)]
    for m in msg_list:
        w = [m[i:i + 32] for i in range(0, len(m), 32)] # 16 elements
        print(w)
        w = w + ([0] * 64)  # extend list length to 80
        for i in range(16, 79):
            w[i] = left_rotate((int(w[i-3]) ^ int(w[i-8]) ^ int(w[i-14]) ^ int(w[i-16])), 1)

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # 4. main loop:
        # didn't feel like writing out all the pseudocode
        for i in range(0, 79):
            if 0 <= i <= 19:
                f = ((b & c) | ((~b) & d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6
            temp = left_rotate(a, 5) + f + e + k + int(w[i])
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp
        
        h0 = h0 + a
        h1 = h1 + b 
        h2 = h2 + c
        h3 = h3 + d
        h4 = h4 + e

    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return hh   #??

print(sha1(b'abc'))