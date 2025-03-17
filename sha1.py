import random
import string
import threading
import requests
import hashlib
import struct

### Tyler Brady and Madeline Park, SHA1 (Task 2, Lab 3)

### Task II: SHA1
# SHA1 helper functions
def ch(x, y, z):
    return (x & y) ^ (~x & z)

def parity(x, y, z):
    return x ^ y ^ z

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def define_k():
    k = [0] * 80
    for i in range(80):
        if 0 <= i <= 19:
            k[i] = 0x5a827999
        elif 20 <= i <= 39:
            k[i] = 0x6ed9eba1
        elif 40 <= i <= 59:
            k[i] = 0x8f1bbcdc
        elif 60 <= i <= 79:
            k[i] = 0xca62c1d6
    return k

def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) % (2 ** 32)

def mod_add(modulus, list_add):
    s = 0
    mod_val = 2 ** modulus
    for i in list_add:
        s = (s + i) % mod_val
    return s

def pad(l):
    bit_len = l * 8
    padding = b'\x80'.hex()
    padding += (b'\x00' * ((56 - (l + 1) % 64) % 64)).hex()
    padding += bit_len.to_bytes(8, 'big').hex()
    return [bytes.fromhex(padding), len(padding)]


    

# SHA1 algorithm
def sha1(msg, H0 = 0x67452301, H1 = 0xefcdab89, H2 = 0x98badcfe, H3 = 0x10325476, H4 = 0xc3d2e1f0, length: int = 0) -> str:
    mod_32 = (2 ** 32)
    # 1. Set initial hash value
    h0, h1, h2, h3, h4 = H0, H1, H2, H3, H4

    k = define_k()
    # 2. Pad message
    byte_str = msg
    if isinstance(msg, str):
        byte_str = msg.encode()

    if length == 0:
        ml = len(byte_str)
    else:
        ml = length
    
    padding = pad(ml)[0]
    byte_str += padding
    print(byte_str)

    blocks = [byte_str[i:i + 64] for i in range(0, len(byte_str), 64)]
    # 3. Prepare the message schedule
    for block in blocks:
        #print(block)
        w = [block[i:i + 4] for i in range(0, len(block), 4)]
        w_ints = []
        w += [b'00' * 8] * (80 - len(w))
        for item in w:
            w_ints.append(int.from_bytes(item, byteorder='big'))

        for t in range(16, 80):
            w_ints[t] = rotl((w_ints[t-3] 
                              ^ w_ints[t-8] 
                              ^ w_ints[t-14] 
                              ^ w_ints[t-16]), 1)
        
        # init working vars with i-1st hash value
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # main loop
        for t in range(0, 80):
            if 0 <= t <= 19:
                f = ch(b, c, d)
            elif 20 <= t <= 39:
                f = parity(b, c, d)
            elif 40 <= t <= 59:
                f = maj(b, c, d)
            elif 60 <= t <= 79:
                f = parity(b, c, d)

            T = mod_add(32, [rotl(a, 5), f, e, k[t], w_ints[t]])
            e = d
            d = c
            c = rotl(b, 30)
            b = a
            a = T

            #print("t=",t, hex(a)[2:], hex(b)[2:], hex(c)[2:], hex(d)[2:], hex(e)[2:])

        # compute ith intermediate hash value
        h0 = (a + h0) % mod_32
        h1 = (b + h1) % mod_32
        h2 = (c + h2) % mod_32
        h3 = (d + h3) % mod_32
        h4 = (e + h4) % mod_32

        """h0 = h0 << 128
        h1 = h1 << 96
        h2 = h2 << 64
        h3 = h3 << 32"""

    #hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    #print(hex(hh))
    return b''.join(struct.pack(b'>I', h) for h in [h0, h1, h2, h3, h4])

#sha1("abc")
print("here???", sha1("YELLOW SUBMARINEFunny names?").hex())

# SHA1 collision test
hash_dict = {}
hash_dict["catch"] = 0
def gen_string(l):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(l))

#print(gen_string(56))

def hash(m, hh): 
    # break into chunks of 50, use as key
    hh = bin(int(hh[2:], 16))[2:] # strip
    for i in range(len(hh) - 50):
        temp_str = hex(int(hh[i:i+50], 2))
        if (temp_str in hash_dict):
            j = hash_dict.get(temp_str)
            if (m != j[1] and i == j[0]):   # not same starting string but same hash
                str = "Collision at " + temp_str + " with strings " + m + " and " + hash_dict.get(temp_str)[1]
                print(str)
                hash_dict["catch"] = 1
        hash_dict[temp_str] = (i, m)

def collision_finder():
    while hash_dict.get("catch") == 0:
        #m = "abc"
        m = gen_string(56) # 2 blocks
        #print(m)
        hash(m, sha1(m))
        #m += 1

if __name__ == "__main__":
    threads = []
    """for i in range(10):
        thread = threading.Thread(target=collision_finder)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("All threads finished")"""

# RESULTS:
"""
Collision at 0x3d91df3b7600d with strings UFMuARZIlh1tXK24glVcT5ykQjXozKrmOOgnUMwcXFogfpyZghcobdS0 and jOj7DCbLpcOaI4XQ69fwwLEmYtusGduUTPX6kB3bYAUh5sUNJy7exDR2
All threads finished
"""


### Task III: SHA1 Keyed MAC
# Length Extension Attack

# plan:
# message digest = sha1(key || message)
# we can set the internal state by reversing the sha1 concat and shift process
# that will give us h0-h4 of the message
# then we need to figure out the length of the message + the key (in bits)
# and include that in our sha1 run
# this will probably have to be done with brute force
# the extended message must be padding as if the entire message was padded
# from sha1: whole input is msg + padding + new
# so we can comput sha1(new) and it'll be like sha1(key || msg || padding || new)
# if we know the length of the key and the length of the message we can figure out
# the length of the padding
# those three get added together and input as the injection length, along with
# the length of the actual injected message


def internal_state(hh):
    temp = hh
    hh = int(temp, 16)
    a = hh >> 128
    b = (hh >> 96) & 0xffffffff
    c = (hh >> 64) & 0xffffffff
    d = (hh >> 32) & 0xffffffff
    e = hh & 0xffffffff
    return [a, b, c, d, e]

def guess_ml(kl):
    orig_msg = b"Funny names?"
    h = internal_state("c8067cc0d4de4e68882cc5273e8c5b1d5839ca65")
    l = kl + len(orig_msg)
    p = pad(l)
    print(p[0])

    add = b"Huh"
    new_msg = orig_msg + p[0] + add
    print(new_msg)
    new_l = l + len(p) + len(add)
    print(new_l)
    new = sha1(b'Funny names?' + b'\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0' + add, h[0], h[1], h[2], h[3], h[4], new_l).hex()
    print("show me to me rachel", new)
    #print(sha1(b'YELLOW SUBMARINEFunny names?\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0Huh').hex())
    j = {"who" : "me", "what": b'Funny names?' + b'\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0' + add, "mac":new}

    requests.post("http://0.0.0.0:8080/", data=j)

#print(sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").hex())


#guess_ml(16)
"""k = b'YELLOW SUBMARINE'
s = b'Funny names?'
x = sha1(b'YELLOW SUBMARINEFunny names?').hex()
print("original:", x)
p = pad((len(k)) + (len(s)))
p0 = p[0]
print("this is", p[1])
h = internal_state(x)
#print(hex((h[0] << 128) | (h[1] << 96) | (h[2] << 64) | (h[3] << 32) | h[4]))
print(sha1(b'Huh', h[0], h[1], h[2], h[3], h[4], ((len(k)) + (len(s))) + len(p[0]) + 3).hex())
print(sha1(k + s + p0 + b'Huh').hex())"""
"""print(k + s + p0 + b'f\xbf\xbd' + b'Huh')
print(len(k + s + p0 + b'Huh'))"""
#print(sha1(b'YELLOW SUBMARINEFunny names?\xef\xbf\xbd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xef\xbf\xbdHuh').hex())


# HMAC
def extend_hex(hstr, ext):
    repeated = []
    for i in range(ext):
        repeated.append(hstr)
    return b''.join([bytes(value) for value in repeated])

def xor(bytes1, bytes2):
    """
    XORs two bytestrings and returns the result as a new bytestring.
    """
    return bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))

def hmac(K, text):
    B = 64
    L = 20
    H = sha1
    #H = hashlib.sha1()
    ipad = extend_hex(b'36', B)
    opad = extend_hex(b'5c', B)

    K0 = ""

    if isinstance(K, str):
        K = K.encode()

    byte_text = text.encode()

    k_len = (K.bit_length() + 7) // 8
    #k_len = len(K)
    print(k_len)

    # 1. If the length of K = B: set K0 = K. 
    if k_len == B:
        K0 = K
    # 2. If the length of K > B: hash K to obtain an L byte string, then append (B-L)
    #    zeros to create a B-byte string K
    elif k_len > B:
        K0 = H(K) + (b'\x00' * (B-L))
    # 3. If the length of K < B: append zeros to the end of K to create a B-byte string K0
    elif k_len < B:
        #print((B-k_len))
        K0 = K + (b'\x00' * (B-k_len))

    # 4. Exclusive-Or K0 with ipad to produce a B-byte string: K0 ⊕ ipad. 
    print(type(ipad))
    k0_ipad = xor(K0, ipad) #int(K0, 16) ^ int(ipad, 16)
    # 5. Append the stream of data 'text' to the string resulting from step 4:
    #    (K0 ⊕ ipad) || text. 
    temp_5 = k0_ipad + byte_text
    #print(temp_5)
    #print(temp)
    # 6. Apply H to the stream generated in step 5: H((K0 ⊕ ipad) || text).
    temp_6 = H(temp_5)
    # 7. Exclusive-Or K0 with opad: K0 ⊕ opad.
    temp_7 = xor(K0, opad)
    # 8. Append the result from step 6 to step 7:
    #    (K0 ⊕ opad) || H((K0 ⊕ ipad) || text). 
    temp_8 = temp_7 + temp_6
    # 9.  Apply H to the result from step 8: 
    #     H((K0 ⊕ opad )|| H((K0 ⊕ ipad) || text)).
    ret = H(temp_8)
    return ret

print(hmac(0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b, "Hi There").hex())
#print(hmac("Jefe", "what do ya want for nothing?").hex())

#sha1("abc")
#print(sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))