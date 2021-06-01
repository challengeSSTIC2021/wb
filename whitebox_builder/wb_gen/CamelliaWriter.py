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

from mycamellia import SBOX, SIGMA, KSFT1, KIDX1


class CamelliaWriter:

    def __init__(self, generator):
        self.generator = generator
        self.sbox = generator.writeTable(SBOX)

    def writePfunction(self, regs):
        for dst in range(4):
            src = 4 + ((dst + 1)%4)
            self.generator.Xor(regs[dst], regs[dst], regs[src])

        for dst in range(4, 8):
            src = ((dst + 2)%4)
            self.generator.Xor(regs[dst], regs[dst], regs[src])

        for dst in range(4):
            src = 4 + ((dst + 3)%4)
            self.generator.Xor(regs[dst], regs[dst], regs[src])

        for dst in range(4, 8):
            src = ((dst + 3)%4)
            self.generator.Xor(regs[dst], regs[dst], regs[src])

    def writeFfunction(self, regs):
        self.generator.UseUniTable(regs[0], self.sbox, regs[0])

        self.generator.UseUniTable(regs[1], self.sbox, regs[1])
        self.generator.Rol(regs[1], regs[1], 1)

        self.generator.UseUniTable(regs[2], self.sbox, regs[2])
        self.generator.Rol(regs[2], regs[2], 7)

        self.generator.Rol(regs[3], regs[3], 1)
        self.generator.UseUniTable(regs[3], self.sbox, regs[3])

        self.generator.UseUniTable(regs[4], self.sbox, regs[4])
        self.generator.Rol(regs[4], regs[4], 1)

        self.generator.UseUniTable(regs[5], self.sbox, regs[5])
        self.generator.Rol(regs[5], regs[5], 7)

        self.generator.Rol(regs[6], regs[6], 1)
        self.generator.UseUniTable(regs[6], self.sbox, regs[6])

        self.generator.UseUniTable(regs[7], self.sbox, regs[7])

    def writeFeistel(self, outregs, inregs, tmpregs, offsetkey=None, tableKey=None):
        assert len(tmpregs) >= 8

        if offsetkey is not None:
            assert type(offsetkey) is list and len(offsetkey) == 8
            for i in range(8):
                self.generator.getInput(tmpregs[i], offsetkey[i])
                self.generator.Xor(tmpregs[i], inregs[i], tmpregs[i])
        else:
            assert type(tableKey) is list and len(tableKey) == 8
            for i in range(8):
                self.generator.setRegister(tmpregs[i], tableKey[i])
                self.generator.Xor(tmpregs[i], inregs[i], tmpregs[i])

        self.writeFfunction(tmpregs)
        self.writePfunction(tmpregs)
        for i in range(8):
            self.generator.Xor(outregs[i], tmpregs[(i+4)%8], outregs[i])

    def writeRolBlock(self, outregs, inregs, tmpregs, n):
        assert 0 <= n and n < (len(inregs) * 8)

        dep = n // 8
        rolv = n % 8
        #print(n, dep, rolv, 8 - rolv, outregs, inregs, tmpregs)
        if rolv == 0:
            for i in range(len(outregs)):
                self.generator.movValue(outregs[i], inregs[ (i+dep) % len(inregs) ])
        else:
            for i in range(len(outregs)):
                self.generator.Shl(outregs[i], inregs[ (i+dep) % len(inregs) ], rolv)
                #print(" - shl ",   outregs[i], inregs[ (i+dep) % len(inregs) ], rolv)
                self.generator.Shr(tmpregs[0], inregs[ (i+dep+1) % len(inregs) ], 8 - rolv)
                #print(" - shr ",   tmpregs[0], inregs[ (i+dep+1) % len(inregs) ], 8 - rolv)
                self.generator.Or(outregs[i], tmpregs[0], outregs[i])
                #print(" - or ",   outregs[i], tmpregs[0], outregs[i])


    def writeFL(self, regs, tmpregs, offsetkey):
        assert len(offsetkey) == 8
        assert len(regs) == 8

        for i in range(4):
            self.generator.getInput(tmpregs[i], offsetkey[i])
            self.generator.And(tmpregs[i], tmpregs[i], regs[i])

        self.writeRolBlock(tmpregs[4:8], tmpregs[0:4], tmpregs[8:], 1)

        for i in range(4):
            self.generator.Xor(regs[4+i], tmpregs[4+i], regs[4+i])

            self.generator.getInput(tmpregs[0], offsetkey[4+i])
            self.generator.Or(tmpregs[0], tmpregs[0], regs[4+i])
            self.generator.Xor(regs[i], regs[i], tmpregs[0])

    def writeFL_inv(self, regs, tmpregs, offsetkey):
        assert len(offsetkey) == 8
        assert len(regs) == 8

        for i in range(4):
            self.generator.getInput(tmpregs[0], offsetkey[4+i])
            self.generator.Or(tmpregs[0], tmpregs[0], regs[4+i])
            self.generator.Xor(regs[i], regs[i], tmpregs[0])

            self.generator.getInput(tmpregs[4+i], offsetkey[i])
            self.generator.And(tmpregs[4+i], tmpregs[4+i], regs[i])

        self.writeRolBlock(tmpregs[0:4], tmpregs[4:8], tmpregs[8:], 1)

        for i in range(4):
            self.generator.Xor(regs[4+i], tmpregs[i], regs[4+i])

    def writeFLlayer(self, regs, tmpregs, offsetkey):
        assert len(offsetkey) == 16
        assert len(regs) == 16

        self.writeFL(regs[0:8], tmpregs, offsetkey[0:8])
        self.writeFL_inv(regs[8:16], tmpregs, offsetkey[8:16])


    def GenerateKeyShedule(self):
        self.generator.reinitRegister()
        key = [self.generator.getNewRegister() for i in range(16)]
        u = [self.generator.getNewRegister() for i in range(16)]
        tmpregs = [self.generator.getNewRegister() for i in range(9)]

        # Copy raw key
        for i in range(16):
            self.generator.getInput(key[i], i)
            self.generator.movValue(u[i], key[i])

        # schedule u
        self.writeFeistel(u[8:16], u[0:8], tmpregs, tableKey=SIGMA[0])
        self.writeFeistel(u[0:8], u[8:16], tmpregs, tableKey=SIGMA[1])
        for i in range(16):
            self.generator.Xor(u[i], key[i], u[i])
        self.writeFeistel(u[8:16], u[0:8], tmpregs, tableKey=SIGMA[2])
        self.writeFeistel(u[0:8], u[8:16], tmpregs, tableKey=SIGMA[3])

        # set output
        v = [key, u]
        for n, r, i in zip(list(range(len(KSFT1))), KSFT1, KIDX1):
            self.writeRolBlock(tmpregs[:8], v[i], tmpregs[8:], r)
            for j in range(8):
                self.generator.setOutput(n*8 + j, tmpregs[j])

        self.generator.Return()

    def encdecInternal(self, m, tmpregs, k_part):

        # load message and apply first key
        for i in range(16):
            self.generator.getInput(m[i], i)
            self.generator.getInput(tmpregs[0], k_part[0][i])
            self.generator.Xor(m[i], m[i], tmpregs[0])

        # round 1-6
        for i in range(3):
            self.writeFeistel(m[8:16], m[0:8], tmpregs, offsetkey=k_part[1+i][0:8])
            self.writeFeistel(m[0:8], m[8:16], tmpregs, offsetkey=k_part[1+i][8:16])

        self.writeFLlayer(m, tmpregs, k_part[4])

        # round 7-12
        for i in range(3):
            self.writeFeistel(m[8:16], m[0:8], tmpregs, offsetkey=k_part[5+i][0:8])
            self.writeFeistel(m[0:8], m[8:16], tmpregs, offsetkey=k_part[5+i][8:16])

        self.writeFLlayer(m, tmpregs, k_part[8])

        # round 13-18
        for i in range(3):
            self.writeFeistel(m[8:16], m[0:8], tmpregs, offsetkey=k_part[9+i][0:8])
            self.writeFeistel(m[0:8], m[8:16], tmpregs, offsetkey=k_part[9+i][8:16])

        # apply last key and store
        for i in range(16):
            self.generator.getInput(tmpregs[0], k_part[12][i])
            self.generator.Xor(m[(i+8)%16], m[(i+8)%16], tmpregs[0])
            self.generator.setOutput(i, m[(i+8)%16])

        self.generator.Return()


    def GenerateEncode(self):
        self.generator.reinitRegister()
        m = [self.generator.getNewRegister() for i in range(16)]
        tmpregs = [self.generator.getNewRegister() for i in range(9)]

        contextoffset = 16
        _k_part = list(range(contextoffset, 13*16 + contextoffset))
        k_part = [_k_part[i:i+16] for i in range(0, len(_k_part), 16)]

        self.encdecInternal(m, tmpregs, k_part)

    def GenerateDecode(self):
        self.generator.reinitRegister()
        m = [self.generator.getNewRegister() for i in range(16)]
        tmpregs = [self.generator.getNewRegister() for i in range(9)]

        contextoffset = 16
        _k_part = list(range(contextoffset, 13*16 + contextoffset))
        k_part = [_k_part[i:i+16] if i in [0, len(_k_part)-16] else (_k_part[i+8:i+16] + _k_part[i:i+8]) for i in range(0, len(_k_part), 16)]
        k_part.reverse()

        self.encdecInternal(m, tmpregs, k_part)


