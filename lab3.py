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
    default_url = check_url(default_urls)
    cipher_url = f"{default_url}/eavesdrop"
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
        check_flag = 0

        # Iterate through all the blocks, up until the second to last one
        for i in range(len(cipher_blocks) - 1):

            cur_block = bytearray(cipher_blocks[i])
            next_block = bytearray(cipher_blocks[i + 1])
            padding = 1
            decrypted_block = []
            block_to_submit = [None, None]


            # Iterate through each byte of the block
            for j in range(len(cur_block) - 1, -1, -1):

                print(f"guessing byte {j}: {cur_block[j]}")
                print(decrypted_block)

                # Try all possible bytes
                for k in range(256):

                
                    if (i == len(cipher_blocks) - 2) and (j == len(cur_block) - 1) and (k == 1):
                        check_flag = 1

                    cur_block[j] ^= k
                    cur_block[j] ^= padding
                    

                    block_to_submit[0] = bytes(cur_block)
                    block_to_submit[1] = bytes(next_block)

                    modified_cookie = b"".join(block_to_submit)
                    
                    modified_cookie_hex = modified_cookie.hex()

                    
                    guess = session.get(f"{default_url}/?enc={modified_cookie_hex}")
                    if (guess.status_code == 404):
                        print(f"found byte {j}. it was {k}")
                        if (check_flag == 0):
                            decrypted_block.append(k)
                            for l in range(len(cur_block) - 1, len(cur_block) - 1 - padding, -1):
                                cur_block[l] ^= padding
                                cur_block[l] ^= padding + 1

                            padding += 1
                            break
                            # last_byte_option = k
                        else:
                            check_flag = 0
                            continue
                    else:
                        cur_block[j] ^= k
                        cur_block[j] ^= padding
            decrypted_block.reverse()        
            final_message.append(decrypted_block)

        return final_message
                        
            

    else:
        print("bad request")

# for i in range(255):
    # print(i)

# ll = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
# padding = 1
# for j in range(len(ll) - 1, len(ll) - 1 - padding, -1):
#    ll[j] = 0

# print(ll)

def do_thing():

    this = guess_padding()

    for i in range(len(this)):
        this[i] = bytes(this[i])

    modified_cookie = b"".join(this)
    modified_cookie_hex = modified_cookie.hex()
                    

    print(modified_cookie)
    return modified_cookie



def timing_attack():
    # http://localhost:8080/?q=foo&mac=46b4ec586117154dacd49d664e5d63fdc88efb51

    # default_url = check_url(default_urls)
    # cipher_url = f"{default_url}/eavesdrop"
    mac = "46b4ec586117154dacd49d664e5d63fdc88efb51"
    cipher_url = f"http://localhost:8080/?q=foo&mac={mac}"
    cipher_bytes = bytes.fromhex(mac)
    final = []
    arr = bytearray(cipher_bytes)
    print(len(arr))
    print(len(cipher_bytes))
    for i in range(len(arr)):
        best_time = 0
        best_guess = None
        for j in range(256):
            arr[i] = j
            thing = bytes(arr)
            hex_submit = thing.hex()




            new_url = f"http://localhost:8080/?q=foo&mac={hex_submit}"
            start = time.perf_counter()
            cipher_sample = requests.get(new_url)
            end = time.perf_counter()
            time_elapsed = end - start
            if time_elapsed > best_time:
                best_time = time_elapsed
                best_guess = j
            
        final.append(best_guess)
        print(best_guess)
    print(final)
    return final

this = timing_attack()
        
    
for i in range(len(this)):
    this[i] = bytes(this[i])

modified_cookie = b"".join(this)
print("wtf")
print(modified_cookie)

    





