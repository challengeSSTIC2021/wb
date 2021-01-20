#!/usr/bin/env python

import sys
import secrets
from mycamellia import camellia_keygen, F_part, bit_xor
from functionP import P_inv
from encodedGenerator import Encode8, Encode8Identity, Encode8XorLinear
from writer import PyWriter, CWriter, VMWriter

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

class GenTableCamellia:

    def __init__(self, key, suffix):
        assert len(key) in [16, 24, 32]
        assert len(suffix) == 8

        self.rawkey = list(key)
        self.key = camellia_keygen(key)
        self.key_part = [self.key[i:i+16] for i in range(0, len(self.key), 16)]
        self.suffix = list(suffix)
        self.table = {}
        self.tableIDs = {}

        self.create()

    def create(self):
        WorldEnc_L1_internal = Encode8XorLinear()
        WorldEnc_L1 = Encode8()
        WorldEnc_R1_internal = Encode8XorLinear()
        WorldEnc_R1 = Encode8()

        class XorLambda:
            def get_xor_table(self, xtab, ytab):
                return xtab, ytab

            def __call__(self, x, y):
                return x ^ y

        self.table['Xor_L1_internal_L1_L1'] = Encode8.binaryTable(WorldEnc_L1, WorldEnc_L1_internal, WorldEnc_L1, XorLambda())
        self.table['Xor_R1_internal_R1_R1'] = Encode8.binaryTable(WorldEnc_R1, WorldEnc_R1_internal, WorldEnc_R1, XorLambda())

        self.table['Xor_L1_internal_clear_L1'] = Encode8.binaryTable(Encode8Identity(), WorldEnc_L1_internal, WorldEnc_L1, XorLambda())
        #self.table['Xor_R1_internal_clear_R1'] = Encode8.binaryTable(WorldEnc_R1_internal, Encode8Identity(), WorldEnc_R1, XorLambda())

        random_left = self.key_part[0][0:8]
        random_right = self.key_part[0][8:16]

        class K_S_lambda_postxor:
            def __init__(self, k1, k2, part):
                self.k2_inv = P_inv(k2)[part]
                self.k1 = k1[part]
                self.part = part

            def __call__(self, x):
                return F_part(x ^ self.k1, self.part) ^ self.k2_inv

        # six first rounds

        n_random = secrets.token_bytes(8)
        self.table['K1_S_lambda_R1_internal'] = [
            Encode8.unaryTable(Encode8Identity(), WorldEnc_R1_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[1][0:8], random_left), bit_xor(n_random, random_right), i))
            for i in range(8)]
        random_right = n_random

        n_random = secrets.token_bytes(8)
        self.table['Xor_R1_internal_suffix_R1'] = [
                    Encode8.unaryTable(WorldEnc_R1_internal, WorldEnc_R1, lambda x: x ^ self.suffix[i] ^ n_random[i] ^ random_right[i])
                for i in range(8)]
        random_right = n_random

        n_random = secrets.token_bytes(8)
        self.table['K2_S_lambda_L1_internal'] = [
            Encode8.unaryTable(WorldEnc_R1, WorldEnc_L1_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[1][8:16], random_right), bit_xor(n_random, random_left), i))
            for i in range(8)]
        random_left = n_random

        n_random = secrets.token_bytes(8)
        self.table['K3_S_lambda_R1_internal'] = [
            Encode8.unaryTable(WorldEnc_L1, WorldEnc_R1_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[2][0:8], random_left), bit_xor(n_random, random_right), i))
            for i in range(8)]
        random_right = n_random

        n_random = secrets.token_bytes(8)
        self.table['K4_S_lambda_L1_internal'] = [
            Encode8.unaryTable(WorldEnc_R1, WorldEnc_L1_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[2][8:16], random_right), bit_xor(n_random, random_left), i))
            for i in range(8)]
        random_left = n_random

        n_random = secrets.token_bytes(8)
        self.table['K5_S_lambda_R1_internal'] = [
            Encode8.unaryTable(WorldEnc_L1, WorldEnc_R1_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[3][0:8], random_left), bit_xor(n_random, random_right), i))
            for i in range(8)]
        random_right = n_random

        n_random = secrets.token_bytes(8)
        self.table['K6_S_lambda_L1_internal'] = [
            Encode8.unaryTable(WorldEnc_R1, WorldEnc_L1_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[3][8:16], random_right), bit_xor(n_random, random_left), i))
            for i in range(8)]
        random_left = n_random

        # First Fl and FL_inv
        # FL is only needed for Left part
        # FL_inv is only needed for Right part
        # need an internal encodage and a new encode after

        WorldEnc_L_Fl1 = Encode8()
        WorldEnc_R_Fl1 = Encode8()
        WorldEnc_L2_internal = Encode8XorLinear()
        WorldEnc_L2 = Encode8()
        WorldEnc_R2_internal = Encode8XorLinear()
        WorldEnc_R2 = Encode8()

        # Fl
        #    t1 = bit_rol(x[0:4], 1)
        #       => 4 bitable from WorldEnc_L1 to WorldEnc_L_Fl1
        #    out1 = bit_xor( x[4:8], bit_and(t1 , bit_rol( k[0:4], 1 )))
        #       => 4 bitable from WorldEnc_L1 and WorldEnc_L_Fl1 to WorldEnc_L2
        #    out0 = bit_xor( x[0:4], bit_or( out1, k[4:8]) )
        #       => 4 bitable from WorldEnc_L1 and WorldEnc_L2 to WorldEnc_L2

        class FL_1:
            def __init__(self, maskLIn, maskTmp, part):
                self.used_mask = maskTmp[part] ^ (( (maskLIn[part] << 1) | (maskLIn[(part+1)%4] >> 7) ) & 0xff)

            def get_xor_table(self, xtab, ytab):
                return [((x<<1) ^ self.used_mask) & 0xfe for x in xtab], [((y>>7) ^ self.used_mask) & 0x1 for y in ytab]

            def __call__(self, x, y):
                return (((x<<1) | (y>>7)) & 0xff) ^ self.used_mask

        class FL_2:
            def __init__(self, maskLIn, maskTmp, maskLOut, key, part):
                self.used_mask = maskLIn[part + 4] ^ maskLOut[part + 4]
                self.used_maskTmp = maskTmp[part]

                self.key = ((key[part] << 1) | (key[(part+1)%4] >> 7)) & 0xff

            def get_xor_table(self, xtab, ytab):
                return [x ^ self.used_mask for x in xtab], [((y ^ self.used_maskTmp) & self.key) for y in ytab]

            def __call__(self, x, y):
                return x ^ self.used_mask ^ ((y ^ self.used_maskTmp) & self.key)

        class FL_3:
            def __init__(self, maskLIn, maskLOut, key, part):
                self.used_mask = maskLIn[part] ^ maskLOut[part]
                self.used_maskLOut = maskLOut[part + 4]
                self.key = key[part + 4]

            def get_xor_table(self, xtab, ytab):
                return [x ^ self.used_mask for x in xtab], [((y ^ self.used_maskLOut) | self.key) for y in ytab]

            def __call__(self, x, y):
                return x ^ self.used_mask ^ ( (y ^ self.used_maskLOut ) | self.key )

        n_random = secrets.token_bytes(8)
        tmp_random = secrets.token_bytes(4)

        self.table['FL_L1to2_tmp'] = [
            Encode8.binaryTable(WorldEnc_L1, WorldEnc_L1, WorldEnc_L_Fl1,
                FL_1(random_left, tmp_random, i))
            for i in range(4)]

        self.table['FL_L1to2_out1'] = [
            Encode8.binaryTable(WorldEnc_L1, WorldEnc_L_Fl1, WorldEnc_L2,
                FL_2(random_left, tmp_random, n_random, self.key_part[4][0:8], i))
            for i in range(4)]

        self.table['FL_L1to2_out0'] = [
            Encode8.binaryTable(WorldEnc_L1, WorldEnc_L2, WorldEnc_L2,
                FL_3(random_left, n_random, self.key_part[4][0:8], i))
            for i in range(4)]

        random_left = n_random

        # Fl_inv
        #    out0 = bit_xor( x[0:4], bit_or( x[4:8], k[4:8]) )
        #       => 4 bitable from WorldEnc_R1 to WorldEnc_R2
        #    t1 = bit_rol( out0, 1)
        #       => 4 bitable from WorldEnc_R2 and WorldEnc_R2 to WorldEnc_R_Fl1
        #    out1 = bit_xor( x[4:8], bit_and( t1, bit_rol( k[0:4], 1)) )
        #       => 4 bitable from WorldEnc_R1 and WorldEnc_R_Fl1 to WorldEnc_R2

        class FL_inv_1:
            def __init__(self, maskRIn, maskROut, key, part):
                self.used_mask = maskRIn[part] ^ maskROut[part]
                self.used_maskRIn = maskRIn[part + 4]
                self.key = key[part + 4]

            def get_xor_table(self, xtab, ytab):
                return [x ^ self.used_mask for x in xtab], [((y ^ self.used_maskRIn) | self.key) for y in ytab]

            def __call__(self, x, y):
                return x ^ self.used_mask ^ ( ( y ^ self.used_maskRIn) | self.key)

        class FL_inv_2:
            def __init__(self, maskROut, maskTmp, part):
                self.used_mask = maskTmp[part] ^ (( (maskROut[part] << 1) | (maskROut[(part+1)%4] >> 7) ) & 0xff)

            def get_xor_table(self, xtab, ytab):
                return [((x<<1) ^ self.used_mask) & 0xfe for x in xtab], [((y>>7) ^ self.used_mask) & 0x1 for y in ytab]

            def __call__(self, x, y):
                return (((x<<1) | (y>>7)) & 0xff) ^ self.used_mask

        class FL_inv_3:
            def __init__(self, maskRIn, maskTmp, maskROut, key, part):
                self.used_mask = maskRIn[part + 4] ^ maskROut[part + 4]
                self.used_maskTmp = maskTmp[part]

                self.key = ((key[part] << 1) | (key[(part+1)%4] >> 7)) & 0xff

            def get_xor_table(self, xtab, ytab):
                return [x ^ self.used_mask for x in xtab], [((y ^ self.used_maskTmp) & self.key) for y in ytab]

            def __call__(self, x, y):
                return x ^ self.used_mask ^ ((y ^ self.used_maskTmp) & self.key)


        n_random = secrets.token_bytes(8)
        tmp_random = secrets.token_bytes(4)

        self.table['FL_R1to2_out0'] = [
            Encode8.binaryTable(WorldEnc_R1, WorldEnc_R1, WorldEnc_R2,
                FL_inv_1(random_right, n_random, self.key_part[4][8:16], i))
            for i in range(4)]

        self.table['FL_R1to2_tmp'] = [
            Encode8.binaryTable(WorldEnc_R2, WorldEnc_R2, WorldEnc_R_Fl1,
                FL_inv_2(n_random, tmp_random, i))
            for i in range(4)]

        self.table['FL_R1to2_out1'] = [
            Encode8.binaryTable(WorldEnc_R1, WorldEnc_R_Fl1, WorldEnc_R2,
                FL_inv_3(random_right, tmp_random, n_random, self.key_part[4][8:16], i))
            for i in range(4)]
        random_right = n_random

        # 7 to 12 rounds
        self.table['Xor_L2_internal_L2_L2'] = Encode8.binaryTable(WorldEnc_L2, WorldEnc_L2_internal, WorldEnc_L2, XorLambda())
        self.table['Xor_R2_internal_R2_R2'] = Encode8.binaryTable(WorldEnc_R2, WorldEnc_R2_internal, WorldEnc_R2, XorLambda())

        n_random = secrets.token_bytes(8)
        self.table['K7_S_lambda_R2_internal'] = [
            Encode8.unaryTable(WorldEnc_L2, WorldEnc_R2_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[5][0:8], random_left), bit_xor(n_random, random_right), i))
            for i in range(8)]
        random_right = n_random

        n_random = secrets.token_bytes(8)
        self.table['K8_S_lambda_L2_internal'] = [
            Encode8.unaryTable(WorldEnc_R2, WorldEnc_L2_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[5][8:16], random_right), bit_xor(n_random, random_left), i))
            for i in range(8)]
        random_left = n_random

        n_random = secrets.token_bytes(8)
        self.table['K9_S_lambda_R2_internal'] = [
            Encode8.unaryTable(WorldEnc_L2, WorldEnc_R2_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[6][0:8], random_left), bit_xor(n_random, random_right), i))
            for i in range(8)]
        random_right = n_random

        n_random = secrets.token_bytes(8)
        self.table['K10_S_lambda_L2_internal'] = [
            Encode8.unaryTable(WorldEnc_R2, WorldEnc_L2_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[6][8:16], random_right), bit_xor(n_random, random_left), i))
            for i in range(8)]
        random_left = n_random

        n_random = secrets.token_bytes(8)
        self.table['K11_S_lambda_R2_internal'] = [
            Encode8.unaryTable(WorldEnc_L2, WorldEnc_R2_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[7][0:8], random_left), bit_xor(n_random, random_right), i))
            for i in range(8)]
        random_right = n_random

        n_random = secrets.token_bytes(8)
        self.table['K12_S_lambda_L2_internal'] = [
            Encode8.unaryTable(WorldEnc_R2, WorldEnc_L2_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[7][8:16], random_right), bit_xor(n_random, random_left), i))
            for i in range(8)]
        random_left = n_random

        # Second Fl and FL_inv

        WorldEnc_L_Fl2 = Encode8()
        WorldEnc_R_Fl2 = Encode8()
        WorldEnc_L3_internal = Encode8XorLinear()
        WorldEnc_L3 = Encode8()
        WorldEnc_R3_internal = Encode8XorLinear()
        WorldEnc_R3 = Encode8()


        n_random = secrets.token_bytes(8)
        tmp_random = secrets.token_bytes(4)

        self.table['FL_L2to3_tmp'] = [
            Encode8.binaryTable(WorldEnc_L2, WorldEnc_L2, WorldEnc_L_Fl2,
                FL_1(random_left, tmp_random, i))
            for i in range(4)]

        self.table['FL_L2to3_out1'] = [
            Encode8.binaryTable(WorldEnc_L2, WorldEnc_L_Fl2, WorldEnc_L3,
                FL_2(random_left, tmp_random, n_random, self.key_part[8][0:8], i))
            for i in range(4)]

        self.table['FL_L2to3_out0'] = [
            Encode8.binaryTable(WorldEnc_L2, WorldEnc_L3, WorldEnc_L3,
                FL_3(random_left, n_random, self.key_part[8][0:8], i))
            for i in range(4)]

        random_left = n_random


        n_random = secrets.token_bytes(8)
        tmp_random = secrets.token_bytes(4)

        self.table['FL_R2to3_out0'] = [
            Encode8.binaryTable(WorldEnc_R2, WorldEnc_R2, WorldEnc_R3,
                FL_inv_1(random_right, n_random, self.key_part[8][8:16], i))
            for i in range(4)]

        self.table['FL_R2to3_tmp'] = [
            Encode8.binaryTable(WorldEnc_R3, WorldEnc_R3, WorldEnc_R_Fl2,
                FL_inv_2(n_random, tmp_random, i))
            for i in range(4)]

        self.table['FL_R2to3_out1'] = [
            Encode8.binaryTable(WorldEnc_R2, WorldEnc_R_Fl2, WorldEnc_R3,
                FL_inv_3(random_right, tmp_random, n_random, self.key_part[8][8:16], i))
            for i in range(4)]
        random_right = n_random

        # 13 to 18 rounds
        self.table['Xor_L3_internal_L3_L3'] = Encode8.binaryTable(WorldEnc_L3, WorldEnc_L3_internal, WorldEnc_L3, XorLambda())
        self.table['Xor_R3_internal_R3_R3'] = Encode8.binaryTable(WorldEnc_R3, WorldEnc_R3_internal, WorldEnc_R3, XorLambda())

        n_random = secrets.token_bytes(8)
        self.table['K13_S_lambda_R3_internal'] = [
            Encode8.unaryTable(WorldEnc_L3, WorldEnc_R3_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[9][0:8], random_left), bit_xor(n_random, random_right), i))
            for i in range(8)]
        random_right = n_random

        n_random = secrets.token_bytes(8)
        self.table['K14_S_lambda_L3_internal'] = [
            Encode8.unaryTable(WorldEnc_R3, WorldEnc_L3_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[9][8:16], random_right), bit_xor(n_random, random_left), i))
            for i in range(8)]
        random_left = n_random

        n_random = secrets.token_bytes(8)
        self.table['K15_S_lambda_R3_internal'] = [
            Encode8.unaryTable(WorldEnc_L3, WorldEnc_R3_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[10][0:8], random_left), bit_xor(n_random, random_right), i))
            for i in range(8)]
        random_right = n_random

        n_random = secrets.token_bytes(8)
        self.table['K16_S_lambda_L3_internal'] = [
            Encode8.unaryTable(WorldEnc_R3, WorldEnc_L3_internal,
                K_S_lambda_postxor(bit_xor(self.key_part[10][8:16], random_right), bit_xor(n_random, random_left), i))
            for i in range(8)]
        random_left = n_random

        if len(self.key_part) == 13:

            n_random = self.key_part[12][0:8]
            self.table['K17_S_lambda_R3_internal'] = [
                Encode8.unaryTable(WorldEnc_L3, WorldEnc_R3_internal,
                    K_S_lambda_postxor(bit_xor(self.key_part[11][0:8], random_left), bit_xor(n_random, random_right), i))
                for i in range(8)]
            random_right = n_random

            n_random = self.key_part[12][8:16]
            self.table['K18_S_lambda_L3_internal'] = [
                Encode8.unaryTable(Encode8Identity(), WorldEnc_L3_internal,
                    K_S_lambda_postxor(bit_xor(self.key_part[11][8:16], random_right), bit_xor(n_random, random_left), i))
                for i in range(8)]
            random_left = n_random

            self.table['Xor_R3_internal_R3_clear'] = Encode8.binaryTable(WorldEnc_R3, WorldEnc_R3_internal, Encode8Identity(), XorLambda())
            self.table['Xor_L3_internal_L3_clear'] = Encode8.binaryTable(WorldEnc_L3, WorldEnc_L3_internal, Encode8Identity(), XorLambda())

        else:

            n_random = secrets.token_bytes(8)
            self.table['K17_S_lambda_R3_internal'] = [
                Encode8.unaryTable(WorldEnc_L3, WorldEnc_R3_internal,
                    K_S_lambda_postxor(bit_xor(self.key_part[11][0:8], random_left), bit_xor(n_random, random_right), i))
                for i in range(8)]
            random_right = n_random

            n_random = secrets.token_bytes(8)
            self.table['K18_S_lambda_L3_internal'] = [
                Encode8.unaryTable(WorldEnc_R3, WorldEnc_L3_internal,
                    K_S_lambda_postxor(bit_xor(self.key_part[11][8:16], random_right), bit_xor(n_random, random_left), i))
                for i in range(8)]
            random_left = n_random

            # Third Fl and FL_inv

            WorldEnc_L_Fl3 = Encode8()
            WorldEnc_R_Fl3 = Encode8()
            WorldEnc_L4_internal = Encode8XorLinear()
            WorldEnc_L4 = Encode8()
            WorldEnc_R4_internal = Encode8XorLinear()
            WorldEnc_R4 = Encode8()


            n_random = secrets.token_bytes(8)
            tmp_random = secrets.token_bytes(4)

            self.table['FL_L3to4_tmp'] = [
                Encode8.binaryTable(WorldEnc_L3, WorldEnc_L3, WorldEnc_L_Fl3,
                    FL_1(random_left, tmp_random, i))
                for i in range(4)]

            self.table['FL_L3to4_out1'] = [
                Encode8.binaryTable(WorldEnc_L3, WorldEnc_L_Fl3, WorldEnc_L4,
                    FL_2(random_left, tmp_random, n_random, self.key_part[12][0:8], i))
                for i in range(4)]

            self.table['FL_L3to4_out0'] = [
                Encode8.binaryTable(WorldEnc_L3, WorldEnc_L4, WorldEnc_L4,
                    FL_3(random_left, n_random, self.key_part[12][0:8], i))
                for i in range(4)]

            random_left = n_random


            n_random = secrets.token_bytes(8)
            tmp_random = secrets.token_bytes(4)

            self.table['FL_R3to4_out0'] = [
                Encode8.binaryTable(WorldEnc_R3, WorldEnc_R3, WorldEnc_R4,
                    FL_inv_1(random_right, n_random, self.key_part[12][8:16], i))
                for i in range(4)]

            self.table['FL_R3to4_tmp'] = [
                Encode8.binaryTable(WorldEnc_R4, WorldEnc_R4, WorldEnc_R_Fl4,
                    FL_inv_2(n_random, tmp_random, i))
                for i in range(4)]

            self.table['FL_R3to4_out1'] = [
                Encode8.binaryTable(WorldEnc_R3, WorldEnc_R_Fl3, WorldEnc_R4,
                    FL_inv_3(random_right, tmp_random, n_random, self.key_part[12][8:16], i))
                for i in range(4)]
            random_right = n_random

            # 19 to 24 rounds
            self.table['Xor_L4_internal_L4_L4'] = Encode8.binaryTable(WorldEnc_L4, WorldEnc_L4_internal, WorldEnc_L4, XorLambda())
            self.table['Xor_R4_internal_R4_R4'] = Encode8.binaryTable(WorldEnc_R4, WorldEnc_R4_internal, WorldEnc_R4, XorLambda())

            n_random = secrets.token_bytes(8)
            self.table['K19_S_lambda_R4_internal'] = [
                Encode8.unaryTable(WorldEnc_L4, WorldEnc_R4_internal,
                    K_S_lambda_postxor(bit_xor(self.key_part[13][0:8], random_left), bit_xor(n_random, random_right), i))
                for i in range(8)]
            random_right = n_random

            n_random = secrets.token_bytes(8)
            self.table['K20_S_lambda_L4_internal'] = [
                Encode8.unaryTable(WorldEnc_R4, WorldEnc_L4_internal,
                    K_S_lambda_postxor(bit_xor(self.key_part[13][8:16], random_right), bit_xor(n_random, random_left), i))
                for i in range(8)]
            random_left = n_random

            n_random = secrets.token_bytes(8)
            self.table['K21_S_lambda_R4_internal'] = [
                Encode8.unaryTable(WorldEnc_L4, WorldEnc_R4_internal,
                    K_S_lambda_postxor(bit_xor(self.key_part[14][0:8], random_left), bit_xor(n_random, random_right), i))
                for i in range(8)]
            random_right = n_random

            n_random = secrets.token_bytes(8)
            self.table['K22_S_lambda_L4_internal'] = [
                Encode8.unaryTable(WorldEnc_R4, WorldEnc_L4_internal,
                    K_S_lambda_postxor(bit_xor(self.key_part[14][8:16], random_right), bit_xor(n_random, random_left), i))
                for i in range(8)]
            random_left = n_random

            n_random = self.key_part[16][0:8]
            self.table['K23_S_lambda_R4_internal'] = [
                Encode8.unaryTable(WorldEnc_L4, WorldEnc_R4_internal,
                    K_S_lambda_postxor(bit_xor(self.key_part[15][0:8], random_left), bit_xor(n_random, random_right), i))
                for i in range(8)]
            random_right = n_random

            n_random = self.key_part[16][8:16]
            self.table['K24_S_lambda_L4_internal'] = [
                Encode8.unaryTable(Encode8Identity(), WorldEnc_L4_internal,
                    K_S_lambda_postxor(bit_xor(self.key_part[15][8:16], random_right), bit_xor(n_random, random_left), i))
                for i in range(8)]
            random_left = n_random

            self.table['Xor_R4_internal_R4_clear'] = Encode8.binaryTable(WorldEnc_R4, WorldEnc_R4_internal, Encode8Identity(), XorLambda())
            self.table['Xor_L4_internal_L4_clear'] = Encode8.binaryTable(WorldEnc_L4, WorldEnc_L4_internal, Encode8Identity(), XorLambda())


    def writeTables(self, writer):
        tableIDs = {}

        for name, table in self.table.items():
            if type(table[0]) == int:
                t = writer.writeTable(table)
            else:
                t = []
                for inTable in table:
                    t.append(writer.writeTable(inTable))

            tableIDs[name] = t
        return tableIDs

    def writeKeyAndSfunction(self, input_var, tmp_var, tableXorSID, writer):
        for i in range(8):
            writer.UseUniTable(tmp_var[i], tableXorSID[i], input_var[i])

    def writePfunction(self, tmp_var, writer):
        #     zl ^= ROL32(zr, 8);
        # t05 = t0 ^ t5
        # t16 = t1 ^ t6
        # t27 = t2 ^ t7
        # t34 = t3 ^ t4
        for dst in range(4):
            src = 4 + ((dst + 1)%4)
            writer.Xor(tmp_var[dst], tmp_var[dst], tmp_var[src])

        #     zr ^= ROL32(zl, 16);
        # t247 = t4 ^ t27
        # t345 = t5 ^ t34
        # t056 = t6 ^ t05
        # t167 = t7 ^ t16
        for dst in range(4, 8):
            src = ((dst + 2)%4)
            writer.Xor(tmp_var[dst], tmp_var[dst], tmp_var[src])

        #     zl ^= ROR32(zr, 8);
        # t01567 = t05 ^ t167
        # t12467 = t16 ^ t247
        # t23457 = t27 ^ t345
        # t03456 = t34 ^ t056
        for dst in range(4):
            src = 4 + ((dst + 3)%4)
            writer.Xor(tmp_var[dst], tmp_var[dst], tmp_var[src])

        #     zr ^= ROR32(zl, 8);
        # t023567 = t247 ^ t03456
        # t013467 = t345 ^ t01567
        # t012457 = t056 ^ t12467
        # t123456 = t167 ^ t23457
        for dst in range(4, 8):
            src = ((dst + 3)%4)
            writer.Xor(tmp_var[dst], tmp_var[dst], tmp_var[src])

    def writeRound(self, input_var, tmp_var, output_var, tableKeySID, tableXorID, writer):
        self.writeKeyAndSfunction(input_var, tmp_var, tableKeySID, writer)
        self.writePfunction(tmp_var, writer)
        for i in range(8):
            writer.UseBiTable(output_var[i], tableXorID, output_var[i], tmp_var[(i+4)%8])

    def writeFl(self, left_var, right_var, tmp_var, table_Ltmp, table_Lout1, table_Lout0, table_Rout0, table_Rtmp, table_Rout1, writer):

        # fl L
        for i in range(4):
            writer.UseBiTable(tmp_var[i], table_Ltmp[i], left_var[i], left_var[(i+1)%4])
        for i in range(4):
            writer.UseBiTable(left_var[i+4], table_Lout1[i], left_var[i+4], tmp_var[i])
        for i in range(4):
            writer.UseBiTable(left_var[i], table_Lout0[i], left_var[i], left_var[i+4])
        # fl R
        for i in range(4):
            writer.UseBiTable(right_var[i], table_Rout0[i], right_var[i], right_var[i+4])
        for i in range(4):
            writer.UseBiTable(tmp_var[i], table_Rtmp[i], right_var[i], right_var[(i+1)%4])
        for i in range(4):
            writer.UseBiTable(right_var[i+4], table_Rout1[i], right_var[i+4], tmp_var[i])

    def debug(self, l_regs, r_regs, tmp_regs, info, tableIDs, writer):
        for i in range(8):
            writer.UseUniTable(tmp_regs[i], tableIDs[info[0]], l_regs[i])
            writer.setRegister(tmp_regs[16], info[2][i])
            writer.Xor(tmp_regs[i], tmp_regs[i], tmp_regs[16]);
        for i in range(8):
            writer.UseUniTable(tmp_regs[i+8], tableIDs[info[1]], r_regs[i])
            writer.setRegister(tmp_regs[16], info[3][i])
            writer.Xor(tmp_regs[i+8], tmp_regs[i+8], tmp_regs[16]);
        writer.print(tmp_regs[:-1])


    def writeCode(self, writerClass):
        writer = writerClass(self.suffix, self.rawkey)
        tableIDs = self.writeTables(writer)

        left_var = [writer.getNewRegister() for i in range(8)]
        right_var = [writer.getNewRegister() for i in range(8)]
        tmp_var = [writer.getNewRegister() for i in range(10)]
        #debug_var = [writer.getNewRegister() for i in range(17)]
        #self.debug(left_var, right_var, debug_var, self.debuginfo, tableIDs, writer)

        # create tmp1
        for i in range(8):
            writer.getInput(left_var[i], i)

        # round 1
        self.writeKeyAndSfunction(left_var, tmp_var, tableIDs['K1_S_lambda_R1_internal'], writer)
        self.writePfunction(tmp_var, writer)
        for i in range(8):
            writer.UseUniTable(right_var[i], tableIDs['Xor_R1_internal_suffix_R1'][i], tmp_var[(i+4)%8])

        # round 2
        self.writeRound(right_var, tmp_var, left_var,
                tableIDs['K2_S_lambda_L1_internal'],
                tableIDs['Xor_L1_internal_clear_L1'],
                writer)
        # round 3
        self.writeRound(left_var, tmp_var, right_var,
                tableIDs['K3_S_lambda_R1_internal'],
                tableIDs['Xor_R1_internal_R1_R1'],
                writer)
        # round 4
        self.writeRound(right_var, tmp_var, left_var,
                tableIDs['K4_S_lambda_L1_internal'],
                tableIDs['Xor_L1_internal_L1_L1'],
                writer)
        # round 5
        self.writeRound(left_var, tmp_var, right_var,
                tableIDs['K5_S_lambda_R1_internal'],
                tableIDs['Xor_R1_internal_R1_R1'],
                writer)
        # round 6
        self.writeRound(right_var, tmp_var, left_var,
                tableIDs['K6_S_lambda_L1_internal'],
                tableIDs['Xor_L1_internal_L1_L1'],
                writer)

        # Fl
        self.writeFl(left_var, right_var, tmp_var,
                tableIDs['FL_L1to2_tmp'],
                tableIDs['FL_L1to2_out1'],
                tableIDs['FL_L1to2_out0'],
                tableIDs['FL_R1to2_out0'],
                tableIDs['FL_R1to2_tmp'],
                tableIDs['FL_R1to2_out1'],
                writer)

        # round 7
        self.writeRound(left_var, tmp_var, right_var,
                tableIDs['K7_S_lambda_R2_internal'],
                tableIDs['Xor_R2_internal_R2_R2'],
                writer)
        # round 8
        self.writeRound(right_var, tmp_var, left_var,
                tableIDs['K8_S_lambda_L2_internal'],
                tableIDs['Xor_L2_internal_L2_L2'],
                writer)
        # round 9
        self.writeRound(left_var, tmp_var, right_var,
                tableIDs['K9_S_lambda_R2_internal'],
                tableIDs['Xor_R2_internal_R2_R2'],
                writer)
        # round 10
        self.writeRound(right_var, tmp_var, left_var,
                tableIDs['K10_S_lambda_L2_internal'],
                tableIDs['Xor_L2_internal_L2_L2'],
                writer)
        # round 11
        self.writeRound(left_var, tmp_var, right_var,
                tableIDs['K11_S_lambda_R2_internal'],
                tableIDs['Xor_R2_internal_R2_R2'],
                writer)
        # round 12
        self.writeRound(right_var, tmp_var, left_var,
                tableIDs['K12_S_lambda_L2_internal'],
                tableIDs['Xor_L2_internal_L2_L2'],
                writer)

        # Fl
        self.writeFl(left_var, right_var, tmp_var,
                tableIDs['FL_L2to3_tmp'],
                tableIDs['FL_L2to3_out1'],
                tableIDs['FL_L2to3_out0'],
                tableIDs['FL_R2to3_out0'],
                tableIDs['FL_R2to3_tmp'],
                tableIDs['FL_R2to3_out1'],
                writer)

        # round 13
        self.writeRound(left_var, tmp_var, right_var,
                tableIDs['K13_S_lambda_R3_internal'],
                tableIDs['Xor_R3_internal_R3_R3'],
                writer)
        # round 14
        self.writeRound(right_var, tmp_var, left_var,
                tableIDs['K14_S_lambda_L3_internal'],
                tableIDs['Xor_L3_internal_L3_L3'],
                writer)
        # round 15
        self.writeRound(left_var, tmp_var, right_var,
                tableIDs['K15_S_lambda_R3_internal'],
                tableIDs['Xor_R3_internal_R3_R3'],
                writer)
        # round 16
        self.writeRound(right_var, tmp_var, left_var,
                tableIDs['K16_S_lambda_L3_internal'],
                tableIDs['Xor_L3_internal_L3_L3'],
                writer)
        if len(self.key_part) == 13:
            # round 17
            self.writeRound(left_var, tmp_var, right_var,
                    tableIDs['K17_S_lambda_R3_internal'],
                    tableIDs['Xor_R3_internal_R3_clear'],
                    writer)
            # round 18
            self.writeRound(right_var, tmp_var, left_var,
                    tableIDs['K18_S_lambda_L3_internal'],
                    tableIDs['Xor_L3_internal_L3_clear'],
                    writer)
        else:
            # round 17
            self.writeRound(left_var, tmp_var, right_var,
                    tableIDs['K17_S_lambda_R3_internal'],
                    tableIDs['Xor_R3_internal_R3_R3'],
                    writer)
            # round 18
            self.writeRound(right_var, tmp_var, left_var,
                    tableIDs['K18_S_lambda_L3_internal'],
                    tableIDs['Xor_L3_internal_L3_L3'],
                    writer)

            # Fl
            self.writeFl(left_var, right_var, tmp_var,
                    tableIDs['FL_L3to4_tmp'],
                    tableIDs['FL_L3to4_out1'],
                    tableIDs['FL_L3to4_out0'],
                    tableIDs['FL_R3to4_out0'],
                    tableIDs['FL_R3to4_tmp'],
                    tableIDs['FL_R3to4_out1'],
                    writer)

            # round 19
            self.writeRound(left_var, tmp_var, right_var,
                    tableIDs['K19_S_lambda_R4_internal'],
                    tableIDs['Xor_R4_internal_R4_R4'],
                    writer)
            # round 20
            self.writeRound(right_var, tmp_var, left_var,
                    tableIDs['K20_S_lambda_L4_internal'],
                    tableIDs['Xor_L4_internal_L4_L4'],
                    writer)
            # round 21
            self.writeRound(left_var, tmp_var, right_var,
                    tableIDs['K21_S_lambda_R4_internal'],
                    tableIDs['Xor_R4_internal_R4_R4'],
                    writer)
            # round 22
            self.writeRound(right_var, tmp_var, left_var,
                    tableIDs['K22_S_lambda_L4_internal'],
                    tableIDs['Xor_L4_internal_L4_L4'],
                    writer)
            # round 23
            self.writeRound(left_var, tmp_var, right_var,
                    tableIDs['K23_S_lambda_R4_internal'],
                    tableIDs['Xor_R4_internal_R4_clear'],
                    writer)
            # round 24
            self.writeRound(right_var, tmp_var, left_var,
                    tableIDs['K24_S_lambda_L4_internal'],
                    tableIDs['Xor_L4_internal_L4_clear'],
                    writer)

        for i in range(8):
            writer.setOutput(i, right_var[i])
        for i in range(8):
            writer.setOutput(i+8, left_var[i])

        writer.Return()
        return writer


if __name__ == '__main__':

    import argparse
    parser = argparse.ArgumentParser()

    class hexArg:

        def __init__(self, size):
            if type(size) is int:
                self.size = [size]
            else:
                self.size = size

        def __call__(self, raw):
            try:
                b = bytes.fromhex(raw)
            except ValueError:
                raise argparse.ArgumentTypeError('Not an hexa value')

            if len(b) not in self.size:
                raise argparse.ArgumentTypeError('Invalid lenght (need {} bytes)'.format(self.size if len(self.size) > 1 else self.size[0]))
            return b

    parser.add_argument("--pyout", type=str, help="export whitebox in a python file")
    parser.add_argument("--cout", type=str, help="export whitebox in a c file")
    parser.add_argument("--vmout", type=str, help="export whitebox in a c file with a VM")
    parser.add_argument("-q", "--quiet", action='store_true', help="Don't display the key")

    parser.add_argument("--suffix", type=hexArg(8), help="whitebox suffix (in hexa) (default: 0000000000000000)")
    parser.add_argument("--aesKey", type=hexArg(16), help="VM aes cipher key (AES-128-CTR) (in hexa) (default: None)")

    groupKey = parser.add_mutually_exclusive_group()
    groupKey.add_argument("--key", type=hexArg([16,24,32]), help="whitebox key (in hexa) (default: a random one)")
    groupKey.add_argument("--lkey",type=int, default=128, choices=[128, 192, 256], help="whitebox key length (default: 128)")

    args = parser.parse_args()

    if not (args.pyout or args.cout or args.vmout):
        parser.error('Error: Need at least --pyout or --cout')

    suffix = args.suffix
    key = args.key

    if not suffix:
        suffix = secrets.token_bytes(8)
    if not key:
        key = secrets.token_bytes(args.lkey // 8)

    if not args.quiet:
        print('Create whitebox for key {} and suffix {}'.format(key.hex(), suffix.hex()))

    whitebox = GenTableCamellia(key, suffix)

    if args.pyout:
        with open(args.pyout, 'w') as f:
            f.write(whitebox.writeCode(PyWriter).Generate())

    if args.cout:
        with open(args.cout, 'w') as f:
            f.write(whitebox.writeCode(CWriter).Generate())

    if args.vmout:
        if not args.quiet and args.aesKey is not None:
            print('Cipher VMTable with {}'.format(args.aesKey.hex()))
        with open(args.vmout, 'w') as f:
            f.write(whitebox.writeCode(VMWriter).Generate(args.aesKey))
