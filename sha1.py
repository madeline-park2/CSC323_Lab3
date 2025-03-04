import random
import string

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

# SHA1 algorithm
def sha1(msg: str) -> str:
    mod_32 = (2 ** 32)
    # 1. Set initial hash value
    h0 = 0x67452301
    h1 = 0xefcdab89
    h2 = 0x98badcfe
    h3 = 0x10325476
    h4 = 0xc3d2e1f0

    k = define_k()

    # 2. Pad message
    bin_str = ''.join(format(ord(i), '08b') for i in msg)
    ml = len(bin_str)

    # append '1' to end of the message
    bin_str += '1'

    # pad with zeros
    num_zeros = (448 - (ml + 1)) % 512

    for i in range(num_zeros):
        bin_str += '0'
    #print(len(bin_str))
    # append original length to the end
    bin_len = format(ml, '#010b')[2:]
    while (len(bin_len) < 63):
        bin_len = '0' + bin_len
    bin_str += bin_len
    #print(bin_str)
    blocks = [bin_str[i:i + 512] for i in range(0, len(bin_str), 512)]
    #print(len(blocks))
    # 3. Prepare the message schedule
    for block in blocks:
        #print(block)
        w = [block[i:i + 32] for i in range(0, len(block), 32)]
        """for a in w:
            print(hex(int(a, 2)))"""
        w_ints = []
        w += ['0' * 32] * (80 - len(w))
        for item in w:
            w_ints.append(int(item, 2))

        for t in range(16, 80):
            w_ints[t] = rotl((w_ints[t-3] 
                              ^ w_ints[t-8] 
                              ^ w_ints[t-14] 
                              ^ w_ints[t-16]), 1)
        
        # init working vars with i-1st hash value?
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

    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    #print(hex(hh))
    return hex(hh)  # returns hex with prefix... maybe change this?

#sha1("abc")
#sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")

# SHA1 collision test
hash_dict = {}
def gen_string(l):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(l))

#print(gen_string(56))

def hash(m, hh): 
    # break into chunks of 50, use as key
    # value is arbitrary i guess?
    hh = bin(int(hh[2:], 16))[2:] # strip
    #print(hh)
    for i in range(len(hh) - 50):
        temp_str = hex(int(hh[i:i+50], 2))
        if temp_str in hash_dict:
            print("Collision at", temp_str, "with strings", m, "and", hash_dict.get(temp_str))
            return True
        hash_dict[temp_str] = m
    return False

def collision_finder():
    catch = False
    while not catch:
        m = gen_string(112) # 4 blocks long
        catch = hash(m, sha1(m))

collision_finder()