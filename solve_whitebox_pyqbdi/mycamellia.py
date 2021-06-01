#!/usr/bin/env python3

# Copyright 2021 Nicolas Surbayrole
# Copyright 2021 Quarkslab
# Copyright 2021 Association STIC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# based on https://embeddedsw.net/zip/Camellia_Original.zip

# XorBlock (only with len() == 16)
def bit_xor(a, b):
    assert len(a) == len(b)
    return [x ^ y for x, y in zip(a, b)]

def bit_or(a, b):
    assert len(a) == len(b)
    return [x | y for x, y in zip(a, b)]

def bit_and(a, b):
    assert len(a) == len(b)
    return [x & y for x, y in zip(a, b)]

# SwapHalf
def swap(a):
    assert len(a) == 16
    return a[8:16] + a[0:8]

def rol1(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xff

def bit_rol(x, n):
    l = len(x)
    assert n <= l * 8
    x_int = int.from_bytes(x, 'big')
    y = ((x_int << n) | (x_int >> (l*8 - n))) & ((1 << (l*8)) - 1)
    return int.to_bytes(y, l, 'big')

# RotBlock
def RotBlock(x, n):
    return bit_rol(x, n)[:8]


def FL(x, k):
    assert len(k) == 8
    assert len(x) == 8

    t1 = bit_xor( x[4:8], bit_rol( bit_and( x[0:4], k[0:4] ), 1) )
    t0 = bit_xor( x[0:4], bit_or( t1, k[4:8]) )

    return t0 + t1

def FL_inv(x, k):
    assert len(k) == 8
    assert len(x) == 8

    t0 = bit_xor( x[0:4], bit_or( x[4:8], k[4:8]) )
    t1 = bit_xor( x[4:8], bit_rol( bit_and( t0, k[0:4] ), 1) )

    return t0 + t1

# Camellia_FLlayer
def FLlayer(x, k):
    assert len(k) == 16
    assert len(x) == 16

    return FL(x[0:8], k[0:8]) + FL_inv(x[8:16], k[8:16])

SBOX = [
    112,130, 44,236,179, 39,192,229,228,133, 87, 53,234, 12,174, 65,
     35,239,107,147, 69, 25,165, 33,237, 14, 79, 78, 29,101,146,189,
    134,184,175,143,124,235, 31,206, 62, 48,220, 95, 94,197, 11, 26,
    166,225, 57,202,213, 71, 93, 61,217,  1, 90,214, 81, 86,108, 77,
    139, 13,154,102,251,204,176, 45,116, 18, 43, 32,240,177,132,153,
    223, 76,203,194, 52,126,118,  5,109,183,169, 49,209, 23,  4,215,
     20, 88, 58, 97,222, 27, 17, 28, 50, 15,156, 22, 83, 24,242, 34,
    254, 68,207,178,195,181,122,145, 36,  8,232,168, 96,252,105, 80,
    170,208,160,125,161,137, 98,151, 84, 91, 30,149,224,255,100,210,
     16,196,  0, 72,163,247,117,219,138,  3,230,218,  9, 63,221,148,
    135, 92,131,  2,205, 74,144, 51,115,103,246,243,157,127,191,226,
     82,155,216, 38,200, 55,198, 59,129,150,111, 75, 19,190, 99, 46,
    233,121,167,140,159,110,188,142, 41,245,249,182, 47,253,180, 89,
    120,152,  6,106,231, 70,113,186,212, 37,171, 66,136,162,141,250,
    114,  7,185, 85,248,238,172, 10, 54, 73, 42,104, 60, 56,241,164,
     64, 40,211,123,187,201, 67,193, 21,227,173,244,119,199,128,158]

_F_part = [
        lambda t: SBOX[t],
        lambda t: rol1(SBOX[t], 1),
        lambda t: rol1(SBOX[t], 7),
        lambda t: SBOX[rol1(t, 1)],
        lambda t: rol1(SBOX[t], 1),
        lambda t: rol1(SBOX[t], 7),
        lambda t: SBOX[rol1(t, 1)],
        lambda t: SBOX[t]
   ]

def F_part(t, p):
    return _F_part[p](t)

def F(t):
    u = [
            SBOX[t[0]],
            rol1(SBOX[t[1]], 1),
            rol1(SBOX[t[2]], 7),
            SBOX[rol1(t[3], 1)],
            rol1(SBOX[t[4]], 1),
            rol1(SBOX[t[5]], 7),
            SBOX[rol1(t[6], 1)],
            SBOX[t[7]]
        ]
    return u

def P(u):
    v = [
        u[0]^     u[2]^u[3]^     u[5]^u[6]^u[7],
        u[0]^u[1]^     u[3]^u[4]^     u[6]^u[7],
        u[0]^u[1]^u[2]^     u[4]^u[5]^     u[7],
             u[1]^u[2]^u[3]^u[4]^u[5]^u[6],
        u[0]^u[1]^               u[5]^u[6]^u[7],
             u[1]^u[2]^     u[4]^     u[6]^u[7],
                  u[2]^u[3]^u[4]^u[5]^     u[7],
        u[0]^          u[3]^u[4]^u[5]^u[6],
    ]

    return v

# Camellia_Feistel
def Feistel(x, y, k):
    assert len(x) == 8
    assert len(y) == 8
    assert len(k) == 8

    return bit_xor(P(F(bit_xor(x, k))), y)

SIGMA = [
    [0xa0,0x9e,0x66,0x7f,0x3b,0xcc,0x90,0x8b],
    [0xb6,0x7a,0xe8,0x58,0x4c,0xaa,0x73,0xb2],
    [0xc6,0xef,0x37,0x2f,0xe9,0x4f,0x82,0xbe],
    [0x54,0xff,0x53,0xa5,0xf1,0xd3,0x6f,0x1c],
    [0x10,0xe5,0x27,0xfa,0xde,0x68,0x2d,0x1d],
    [0xb0,0x56,0x88,0xc2,0xb3,0xe6,0xc1,0xfd]]

KSFT1 = [0,64,0,64, 15,79,15,79, 30,94,45,109,45,124,60,124,77,13, 94,30,94,30, 111,47,111,47]
KIDX1 = [0, 0,1, 1,  0, 0, 1, 1,  1, 1, 0,  0, 1,  0, 1,  1, 0, 0,  0, 0, 1, 1,   0, 0,  1, 1]

KSFT2 = [0,64,0,64,15,79,15,79,30,94,30,94,45,109,45,109,60,124,60,124,60,124,77,13,77,13,94,30,94,30,111,47,111,47]
KIDX2 = [0,0,3,3,2,2,1,1,2,2,3,3,0,0,1,1,0,0,2,2,3,3,0,0,1,1,2,2,1,1,0,0,3,3]

def camellia_keygen(k):

    n = len(k)*8
    assert n in [128, 192, 256]
    e = []

    t = list(k)
    if n == 128:
        t += [0] * 16
    elif n == 192:
        t += k[16:24]
    assert len(t) == 32

    u = bit_xor(t[0:16], t[16:32])

    u[8:16] = Feistel(u[0:8], u[8:16], SIGMA[0])
    u[0:8] = Feistel(u[8:16], u[0:8], SIGMA[1])

    u = bit_xor(t[0:16], u)

    u[8:16] = Feistel(u[0:8], u[8:16], SIGMA[2])
    u[0:8] = Feistel(u[8:16], u[0:8], SIGMA[3])

    if n == 128:
        v = [t[0:16], u]
        for r, i in zip(KSFT1, KIDX1):
            e += RotBlock(v[i] ,r)

    else:
        w = bit_xor(t[16:32], u)
        w[8:16] = Feistel(w[0:8], u[8:16], SIGMA[4])
        w[0:8] = Feistel(w[8:16], u[0:8], SIGMA[5])

        v = [t[0:16], u, t[16:32], w]
        for r, i in zip(KSFT2, KIDX2):
            e += RotBlock(v[i] ,r)

    return e

def camellia_internal(k_part, plain):
    assert len(plain) == 16

    c = list(plain)

    for i in range(3 if len(k_part) == 13 else 4):
        if (i == 0):
            c = bit_xor(c, k_part[0])
        else:
            c = FLlayer(c, k_part[i*4])

        for j in range(1, 4):
            c[8:16] = Feistel(c[0:8], c[8:16], k_part[i*4 + j][0:8])
            c[0:8] = Feistel(c[8:16], c[0:8], k_part[i*4 + j][8:16])

    return bit_xor(swap(c), k_part[-1])

def camellia_enc(k, plain):

    assert len(k) in [208, 272]
    k_part = [k[i:i+16] for i in range(0, len(k), 16)]

    return bytes(camellia_internal(k_part, plain))

def camellia_dec(k, plain):

    assert len(k) in [208, 272]
    k_part = [k[i:i+16] if i in [0, len(k)-16] else swap(k[i:i+16]) for i in range(0, len(k), 16)]
    k_part.reverse()

    return bytes(camellia_internal(k_part, plain))


if __name__ == '__main__':
    key = b"\x00" * 32
    plain = b"\x00" * 16
    print('my plain  : {}'.format(plain.hex()))

    impl_key = camellia_keygen(key)
    cipher = camellia_enc(impl_key, plain)
    out = camellia_dec(impl_key, cipher)

    print('my cipher : {}'.format(cipher.hex()) )
    print('uncipher  : {}'.format(out.hex()))
    assert out == plain

    import camellia
    c1 = camellia.CamelliaCipher(key=key, mode=camellia.MODE_ECB)
    cipher2 = c1.encrypt(plain)

    assert cipher == cipher2
