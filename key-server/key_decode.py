#!/usr/bin/env python

import camellia
from hashlib import sha256

MASTER_KEY = bytes.fromhex("8899aabbccddeeff0011223344556677")
VM_EXPIRE = 1000

def VM_decode(payload):
    if type(payload) != bytes or len(payload) != 20:
        return None

    cipher = payload[:16]
    ident = payload[16:]

    key = sha256(MASTER_KEY + ident).digest()[:16]

    c1 = camellia.CamelliaCipher(key=key, mode=camellia.MODE_ECB)
    return c1.decrypt(cipher)

