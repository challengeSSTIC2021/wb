#!/usr/bin/env python

from mycamellia import P

__all__ = ['P', 'P_inv', 'gauss_invert']

def Pconv(t):
    u = []
    for i in range(0, 64, 8):
        u.append((t>>i) & 0xff)

    v = P(u)
    w = 0
    for i in range(8):
        w |= ( v[i] << (i*8) )

    return w

def gauss_invert(l=64, method=Pconv):
    t = []
    for i in range(l):
        t.append([1<<i, method(1<<i)])

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

inv_feistel = gauss_invert()

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
    assert error == 0

    import random
    for i in range(4096):
        t = [random.randint(0, 255) for i in range(8)]
        t_inv = P_inv(t)
        t_m = P(t_inv)
        if t != t_m:
            print('[KO] P_inv (t: {}, t_inv: {}, t_m: {})'.format(t, t_inv, t_m))
            error +=1
    assert error == 0
    print('[OK] P_inv')


