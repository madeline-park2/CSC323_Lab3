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
        correct_flag = 0
        last_byte_option = None
        # Iterate through all the blocks, starting at the second to last one
        
        for i in range(len(cipher_blocks)):


            

            cur_block = bytearray(cipher_blocks[i])
            next_block = bytearray(cipher_blocks[i + 1])
            padding = 1
            block_block = []
            final_block = []
            # block = bytearray(cipher_blocks[i])

            # Iterate through each byte of the block
            for j in range(len(cur_block) - 1, -1, -1):
                if (i == len(cipher_blocks) - 1) and (j == len(cur_block) - 1):
                    correct_flag = 1
                # Try all possible bytes
                for k in range(255):

                    cur_block[j] ^= k
                    cur_block[j] ^= padding
                    

                    # cipher_blocks[i] = bytes(cur_block)
                    final_block.append(bytes(cur_block))
                    final_block.append(bytes(next_block))

                    modified_cookie = b"".join(final_block)
                    
                    modified_cookie_hex = modified_cookie.hex()

                    
                    guess = session.get(f"{default_url}/?enc={modified_cookie_hex}")
                    if (guess.status_code == 404):
                        if (correct_flag != 1):
                            last_byte_option = k
                        else:

                            for l in range(len(cur_block) - 1, len(cur_block) - 1 - padding - 1, -1):
                                cur_block[l] ^= padding
                                cur_block[l] ^= padding + 1
                            block_block.append(k)
                            padding += 1
                            break
                            
                

            final_message.append(block_block)
        




        return final_message
                        
            

    else:
        print("bad request")


ll = [1, 2, 3 ,4]

for j in range(len(ll) - 1, -1, -1):
    print(j)




# this = guess_padding()
# print("\n")
# print(this)
# print("\n")
# print(len(this))
# yes = bytes(this[0])
# print(yes)
# print("\n")
# print("AAAAAAAHHHHHHHHHHHH")
# hexstr = yes.hex()
# print("\n")
# print(hexstr)

    # for block in blocks:
    #     block_arr = bytearray(block)

#     for byte in block_arr: