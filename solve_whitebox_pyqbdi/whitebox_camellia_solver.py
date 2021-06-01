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

from mycamellia import bit_xor, bit_rol, swap, _F_part, KSFT1, camellia_keygen, Feistel
from functionP import P_inv


class WhiteboxCamellia128Solver:

    def __init__(self, encrypt, first_round, round15, round16, round17, last_round, suffix):
        self.encrypt = encrypt
        self.first_round = first_round
        self.round15 = round15
        self.round16 = round16
        self.round17 = round17
        self.last_round = last_round
        self.suffix = suffix

        self.default_plain = bytes([0] * 8) + self.suffix

        self.default_state_before_15 = self.first_round(self.default_plain)
        self.default_state_before_16 = self.round15(self.default_state_before_15)
        self.default_state_before_17 = self.round16(self.default_state_before_16)
        self.default_state_before_18 = self.round17(self.default_state_before_17)
        self.default_cipher = self.last_round(self.default_state_before_18)

        assert self.encrypt(self.default_plain) == self.default_cipher

        self.key_r18 = None
        self.key_r17 = None
        self.key_r16 = None
        self.key_r15 = None
        self.key = None

    def computeKey(self):
        if self.key:
            return self.key

        print("get key_r18")
        self.key_r18 = self.extract_key(self.bf_18()) # key_12 [8:] ^ key_13 [:8]
        print("get key_r17")
        self.key_r17 = self.extract_key(self.bf_17()) # key_12 [:8] ^ key_13 [8:]
        print("get key_r16")
        self.key_r16 = self.extract_key(self.bf_16()) # key_11 [8:] ^ key_13 [:8]
        print("get key_r15")
        self.key_r15 = self.extract_key(self.bf_15()) # key_11 [:8] ^ key_13 [8:]

        self.key = self.extract_key_camellia128(self.key_r15 + self.key_r16, self.key_r17 + self.key_r18)
        return self.key

    def verify(self):
        import camellia
        c1 = camellia.CamelliaCipher(key=self.computeKey(), mode=camellia.MODE_ECB)
        assert c1.encrypt(self.default_plain) == self.default_cipher

        import secrets
        for i in range(256):
            x = secrets.token_bytes(8) + self.suffix
            assert c1.encrypt(x) == self.encrypt(x)


    @staticmethod
    def extract_key(bf):
        key = []

        for i in range(len(bf)):
            log_index = bf[i][:]
            log_index.sort(key=lambda x: x[0])

            diff_res = [(1<<j, log_index[0][1] ^ log_index[1<<j][1]) for j in range(8)]
            f = _F_part[i]

            for i in range(256):
                assert log_index[i][0] == i

            def key_verify(index):
                for diff in diff_res:
                    if diff[1] != f(index) ^ f(index ^ diff[0]):
                        return False
                return True

            subkey = []
            for j in range(256):
                if key_verify(j):
                    subkey.append(j)

            assert len(subkey) == 1
            subkey = subkey[0]

            # validation
            subkey2 = f(subkey) ^ log_index[0][1]
            for index in range(256):
                assert f(index ^ subkey) ^ subkey2 == log_index[index][1]

            key.append(subkey)
        return key

    def bf_15(self):
        assert self.key_r18 is not None
        assert self.key_r17 is not None
        assert self.key_r16 is not None

        res = []
        ref_g18 = Feistel(self.default_cipher[:8], self.default_cipher[8:], self.key_r18)
        ref_d17 = Feistel(ref_g18, self.default_cipher[:8], self.key_r17)

        ref1 = Feistel(ref_d17, ref_g18, self.key_r16)
        ref2 = P_inv(ref_d17)
        for i in range(8):
            tmpres = []

            for j in range(256):
                x = self.default_state_before_15[:]
                x[i] = j
                r15 = list(self.round15(x))

                # dir
                r16_dir = self.round16(r15[:8] + self.default_state_before_16[8:])
                r_dir = Feistel(ref_d17 ,Feistel(self.default_cipher[:8], self.last_round(r16_dir[:8] + self.default_state_before_18[8:])[8:], self.key_r18), self.key_r16)

                # inv
                r_inv = P_inv(Feistel(ref_g18, self.last_round(self.round17(self.default_state_before_17[:8] + r15[8:]))[:8], self.key_r17))

                assert r_dir[:i] == ref1[:i]
                assert r_dir[i+1:] == ref1[i+1:]
                assert r_inv[:i] == ref2[:i]
                assert r_inv[i+1:] == ref2[i+1:]
                tmpres.append( (r_dir[i], r_inv[i]) )
            res.append(tmpres)
        return res

    def bf_16(self):
        assert self.key_r18 is not None
        assert self.key_r17 is not None

        res = []
        ref_g18 = Feistel(self.default_cipher[:8], self.default_cipher[8:], self.key_r18)

        ref1 = Feistel(ref_g18, self.default_cipher[:8], self.key_r17)
        ref2 = P_inv(ref_g18)
        for i in range(8):
            tmpres = []

            for j in range(256):
                x = self.default_state_before_16[:]
                x[8+i] = j
                r16 = list(self.round16(x))

                # dir
                r_dir = Feistel(ref_g18, self.last_round(self.round17(self.default_state_before_17[:8] + r16[8:]))[:8], self.key_r17)

                # inv
                r_inv = P_inv(Feistel(self.default_cipher[:8], self.last_round(r16[:8] + self.default_state_before_18[8:])[8:], self.key_r18))

                assert r_dir[:i] == ref1[:i]
                assert r_dir[i+1:] == ref1[i+1:]
                assert r_inv[:i] == ref2[:i]
                assert r_inv[i+1:] == ref2[i+1:]
                tmpres.append( (r_dir[i], r_inv[i]) )
            res.append(tmpres)
        return res

    def bf_17(self):
        assert self.key_r18 is not None

        res = []
        ref1 = Feistel(self.default_cipher[:8], self.default_cipher[8:], self.key_r18)
        ref2 = P_inv(self.default_cipher[:8])
        for i in range(8):
            tmpres = []

            for j in range(256):
                x = self.default_state_before_17[:]
                x[i] = j
                r17 = list(self.round17(x))

                r_dir = Feistel(self.default_cipher[:8], list(self.last_round(r17[:8] + self.default_state_before_18[8:]))[8:], self.key_r18)

                r_inv = P_inv(self.last_round(r17)[:8])

                assert r_dir[:i] == ref1[:i]
                assert r_dir[i+1:] == ref1[i+1:]
                assert r_inv[:i] == ref2[:i]
                assert r_inv[i+1:] == ref2[i+1:]
                tmpres.append( (r_dir[i], r_inv[i]) )
            res.append(tmpres)
        return res

    def bf_18(self):

        res = []
        ref1 = list(self.default_cipher[:8])
        ref2 = P_inv(self.default_cipher[8:])
        for i in range(8):
            tmpres = []

            for j in range(256):
                x = self.default_state_before_18[:]
                x[8+i] = j
                r = list(self.last_round(x))
                r_dir = r[:8]
                r_inv = P_inv(r[8:])
                assert r_dir[:i] == ref1[:i]
                assert r_dir[i+1:] == ref1[i+1:8]
                assert r_inv[:i] == ref2[:i]
                assert r_inv[i+1:8] == ref2[i+1:8]
                tmpres.append( (r[i], r_inv[i]) )
            res.append(tmpres)
        return res

    @staticmethod
    def extract_key_camellia128(key_11_13, key_12_13):
        offset_13 = KSFT1[24]
        offset_12 = KSFT1[22]
        offset_11 = KSFT1[20]
        assert KSFT1[25] == (offset_13 + 64) % 128
        assert KSFT1[23] == (offset_12 + 64) % 128
        assert KSFT1[21] == (offset_11 + 64) % 128

        m = [0xff] * 16

        k = int.from_bytes(bit_rol(bytes(key_11_13), 128 - offset_11), 'big')
        next_pos = lambda x: (x + 128 + 64 + offset_13 - offset_11) % 128
        u = k & 1
        current_bit = k & 1
        pos = next_pos(0)
        for i in range(127):
            assert pos != 0
            current_bit = ((k >> pos) ^ current_bit) & 1
            u |= current_bit << pos
            pos = next_pos(pos)
        assert pos == 0
        assert current_bit ^ (k & 1) == u & 1

        u = int.to_bytes(u, 16, 'big')

        assert bit_xor(bit_rol(u, offset_11), swap(bit_rol(u, offset_13))) == key_11_13
        assert bit_xor(bit_rol(bit_xor(u, m), offset_11), swap(bit_rol(bit_xor(u, m), offset_13))) == key_11_13

        rot_key12 = bit_xor(key_12_13, swap(bit_rol(u, offset_13)))
        key12 = bit_rol(rot_key12, (128 - offset_12) % 128)

        assert bit_xor(bit_rol(key12, offset_12), swap(bit_rol(u, offset_13))) == key_12_13
        assert camellia_keygen(key12)[22*8:24*8] == list(bit_rol(key12, offset_12))

        assert bit_xor(bit_rol(bit_xor(key12, m), offset_12), swap(bit_rol(bit_xor(u, m), offset_13))) == key_12_13
        assert camellia_keygen(bit_xor(key12, m))[22*8:24*8] == list(bit_rol(bit_xor(key12, m), offset_12))

        r1 = list(camellia_keygen(key12)[16:32]) == list(u)
        r2 = list(camellia_keygen(bit_xor(key12, m))[16:32]) == list(bit_xor(u, m))

        assert r1 ^ r2 == 1
        if r1:
            return bytes(key12)
        else:
            return bytes(bit_xor(key12, m))

