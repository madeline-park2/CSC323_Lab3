import random
import string
import threading

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

def init_h(h0, h1, h2, h3, h4):
    return h0, h1, h2, h3, h4
    

# SHA1 algorithm
def sha1(msg: str) -> str:
    mod_32 = (2 ** 32)
    # 1. Set initial hash value
    h0, h1, h2, h3, h4 = init_h(0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)

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

    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    #print(hex(hh))
    return hex(hh)  # returns hex with prefix

#sha1("abc")
#print(sha1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))

# SHA1 collision test
hash_dict = {}
def gen_string(l):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(l))

#print(gen_string(56))

def hash(m, hh): 
    # break into chunks of 50, use as key
    hh = bin(int(hh[2:], 16))[2:] # strip
    for i in range(len(hh) - 50):
        temp_str = hex(int(hh[i:i+50], 2))
        if (temp_str in hash_dict): #and (hash_dict.get(temp_str)[0] == i) and (m != hash_dict.get(temp_str)[1]):
            j = hash_dict.get(temp_str)
            if (m != j[1] and i == j[0]):   # not same starting string but same hash
                str = "Collision at " + temp_str + " with strings " + m + " and " + hash_dict.get(temp_str)[1]
                print(str)
                return True
        hash_dict[temp_str] = (i, m)
    return False

def collision_finder():
    catch = False
    while not catch:
        #m = "abc"
        m = gen_string(28) # 1 block
        #print(m)
        catch = hash(m, sha1(m))
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

### Task III: SHA1 Keyed MAC
# Length Extension Attack
# can reconstruct internal state from hash digest
# pad, then extend

# we're given the original message and the signature
# use post request?

# we know the internal state (a, b, c, d, e) because that's what makes
# up the final digest (but how do we get that from the signature?)
# it's H(k || m)
# so we can feed that into initial h0-h4 values, put on proper padding
# to get to that state
# then put in just the padding and new data?
# hash with SHA1, output should be a valid extension of the original?

def internal_state(hh):
    hh = int(hh, 16)
    a = hh >> 128
    b = (hh >> 96) & 0xffffffff
    c = (hh >> 64) & 0xffffffff
    d = (hh >> 32) & 0xffffffff
    e = hh & 0xffffffff
    return [a, b, c, d, e]
