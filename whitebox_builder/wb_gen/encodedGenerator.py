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

import random

class Encode8:

    def __init__(self):
        self.encoded = list(range(256))
        random.shuffle(self.encoded)
        self.plain = [None for i in range(256)]
        for i, n in enumerate(self.encoded):
            self.plain[n] = i

    def getEncodeTable(self):
        return self.encoded

    def getDecodeTable(self):
        return self.plain

    @staticmethod
    def unaryTable(inputEnc, outputEnc, foo):
        inEnc = inputEnc.getDecodeTable()
        dest = outputEnc.getEncodeTable()
        return [dest[foo(inEnc[i])] for i in range(256)]

    @staticmethod
    def binaryTable(input0Enc, input1Enc, outputEnc, foo):
        inEnc0 = input0Enc.getDecodeTable()
        inEnc1 = input1Enc.getDecodeTable()
        dest = outputEnc.getEncodeTable()

        if hasattr(foo, 'get_xor_table'):
            xmem, ymem = foo.get_xor_table(inEnc0, inEnc1)
            return [dest[x ^ y] for x in xmem for y in ymem]
        else:
            return [dest[foo(inEnc0[i], inEnc1[j])] for i in range(256) for j in range(256)]

class Encode8Identity(Encode8):

    def __init__(self):
        self.encoded = list(range(256))
        self.plain = list(range(256))

class Encode8XorLinear(Encode8):

    def __init__(self):
        unused = set(range(1, 256))
        for i in [1, 2, 4, 8, 16, 32, 64, 128]:
            unused.discard(i)

        used = set([0])
        selected = []
        for i in range(8):
            v = random.choice(list(unused))
            new_used = set()
            for u in used:
                assert (v ^ u) not in used
                assert (v ^ u) in (unused | set([1, 2, 4, 8, 16, 32, 64, 128]))
                new_used.add(v ^ u)
            used |= new_used
            unused -= new_used
            selected.append(v)
        assert len(unused) == 0
        assert len(used) == 256

        self.encoded = [None for i in range(256)]
        self.plain = [None for i in range(256)]

        for i in range(256):
            v = 0
            for j in range(8):
                if ((i >> j) & 1) == 1:
                    v ^= selected[j]
            self.encoded[i] = v
            assert self.plain[v] == None
            self.plain[v] = i


if __name__ == '__main__':

    for _ in range(32):
        obj = Encode8()
        enc = obj.getEncodeTable()
        dec = obj.getDecodeTable()
        for i in range(256):
            assert dec[enc[i]] == i, "Encode8 encodage error"
    print("[OK] Encode8")

    for _ in range(32):
        obj = Encode8Identity()
        enc = obj.getEncodeTable()
        dec = obj.getDecodeTable()
        for i in range(256):
            assert dec[enc[i]] == i, "Encode8Identity encodage error"
            assert enc[i] == i, "Encode8Identity identity error"
    print("[OK] Encode8Identity")

    for _ in range(32):
        obj = Encode8XorLinear()
        enc = obj.getEncodeTable()
        dec = obj.getDecodeTable()
        for i in range(256):
            assert dec[enc[i]] == i, "Encode8XorLinear encodage error"
        for i in range(256):
            for j in range(256):
                assert dec[enc[i] ^ enc[j]] == i ^ j, "Encode8XorLinear xor linear error"
    print("[OK] Encode8XorLinear")

    for _ in range(32):
        objSrc = random.choice([Encode8, Encode8Identity, Encode8XorLinear])()
        objDst = random.choice([Encode8, Encode8Identity, Encode8XorLinear])()

        enc = objDst.getEncodeTable()
        dec = objSrc.getDecodeTable()

        for i in range(16):
            t = Encode8.unaryTable(objSrc, objDst, lambda x: x ^ i)
            for j in range(256):
                assert t[j] == enc[dec[j] ^ i], "wrong table"

    print("[OK] unaryTable")

    for _ in range(8):
        objSrc1 = random.choice([Encode8, Encode8Identity, Encode8XorLinear])()
        objSrc2 = random.choice([Encode8, Encode8Identity, Encode8XorLinear])()
        objDst = random.choice([Encode8, Encode8Identity, Encode8XorLinear])()

        enc = objDst.getEncodeTable()
        dec1 = objSrc1.getDecodeTable()
        dec2 = objSrc2.getDecodeTable()

        for _ in range(4):
            t = Encode8.binaryTable(objSrc1, objSrc2, objDst, lambda x, y: x ^ ((y+10) % 16))
            for i in range(256):
                for j in range(256):
                    assert t[i*256 + j] == enc[dec1[i] ^ ((dec2[j] + 10 ) % 16)], "wrong table"

    print("[OK] binaryTable")
