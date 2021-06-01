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

from mycamellia import P

__all__ = ['P', 'P_inv']

def Pconv(t):
    u = []
    for i in range(0, 64, 8):
        u.append((t>>i) & 0xff)

    v = P(u)
    w = 0
    for i in range(8):
        w |= ( v[i] << (i*8) )

    return w

def _inverse_P(l=64):
    t = []
    for i in range(l):
        t.append([1<<i, Pconv(1<<i)])

    ## gauss inversion
    for i in range(l):
        t.sort(reverse=True, key=lambda x: x[1])
        x0, y0 = t[i]
        for j in range(i+1, l):
            x, y = t[j]
            if (y & 1<<(l-(i+1))) != 0:
                t[j] = (x^x0, y^y0)

    t.sort(key=lambda x: x[1])
    for i in range(l):
        x0, y0 = t[i]
        for j in range(i+1, l):
            x, y = t[j]
            if (y & 1<<i) != 0:
                t[j] = (x^x0, y^y0)

    return [x for x,_ in t]

inv_feistel = _inverse_P()

def P_inv(t):
    v = 0
    for i in range(8):
        for j in range(8):
            if (t[i] & (1<<j)) != 0:
                v ^= inv_feistel[i*8+j]

    w = []
    for i in range(0, 64, 8):
        w.append((v>>i) & 0xff)

    return w


if __name__ == '__main__':
    print(inv_feistel)

    error = 0

    for i in range(256):
        t = list(int.to_bytes(i, 8, 'big'))
        t_inv = P_inv(t)
        t_m = P(t_inv)
        if t != t_m:
            print('[KO] P_inv (t: {}, t_inv: {}, t_m: {})'.format(t, t_inv, t_m))
            error +=1
    import random
    assert error == 0

    for i in range(4096):
        t = [random.randint(0, 255) for i in range(8)]
        t_inv = P_inv(t)
        t_m = P(t_inv)
        if t != t_m:
            print('[KO] P_inv (t: {}, t_inv: {}, t_m: {})'.format(t, t_inv, t_m))
            error +=1
    assert error == 0
    print('[OK] P_inv')


