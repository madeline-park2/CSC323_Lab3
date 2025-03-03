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
    bin_str = res = ''.join(format(ord(i), '08b') for i in msg)
    ml = len(bin_str)
    # append '1' to end of the message
    bin_str += '1'
    #print(bin_str)
    # pad with zeros
    num_zeros = (448 % 512) - (ml + 1)
    for i in range(num_zeros):
        bin_str += '0'
    #print(len(bin_str))
    # append original length to the end
    bin_len= format(ml, '#010b')[2:]
    for i in range(0, 64 - len(bin_len)):
        bin_str += '0'
    bin_str += bin_len
    #print(bin_str)
    blocks = [bin_str[i:i + 512] for i in range(0, len(bin_str), 512)]
    # 3. Prepare the message schedule
    for block in blocks:
        w_ints = []
        w = [block[i:i + 32] for i in range(0, len(block), 32)]
        w += ['0' * 32] * 64
        for item in w:
            w_ints.append(int(item, 2))
        #print(w_ints)
        #print(w)
        for t in range(16, 79):
            #print(int(str(w[t]), 2))
            #print(int(w[t-3], 2))
            
            #w[t] = int(w[t-3], 2)
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
        for t in range(0, 79):
            if 0 <= t <= 19:
                f = ch(b, c, d)
            elif 20 <= t <= 39:
                f = parity(b, c, d)
            elif 40 <= t <= 59:
                f = maj(b, c, d)
            elif 60 <= t <= 79:
                f = parity(b, c, d)

            print(k[t])
            T = mod_add(32, [rotl(a, 5), f, e, k[t], w_ints[t]])
            #T = rotl(a, 5) + f + e + k[t] + w_ints[t]
            e = d
            d = c
            c = rotl(b, 30)
            #c = b
            b = a
            a = T

            print("t=",t, hex(a)[2:], hex(b)[2:], hex(c)[2:], hex(d)[2:], hex(e)[2:])
            #print("s=", len(hex(a)[2:]), len(hex(b)[2:]), len(hex(c)[2:]), len(hex(d)[2:]), len(hex(e)[2:]))

        # compute ith intermediate hash value
        h0 = (a + h0) % mod_32
        h1 = (b + h1) % mod_32
        h2 = (c + h2) % mod_32
        h3 = (d + h3) % mod_32
        h4 = (e + h4) % mod_32

    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    #hh = (hex(h0), hex(h1), hex(h2), hex(h3), hex(h4))
    print(hex(hh))


sha1("abc")