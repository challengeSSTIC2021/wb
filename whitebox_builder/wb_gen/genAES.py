#!/usr/bin/env python3


def genHeader(key):

    context = {}
    context['key'] = ", ".join([repr(i) for i in key])

    res = """
#ifndef AESKEY_H
#define AESKEY_H

static unsigned char AESKey[16] = {{ {key} }};

#endif
"""

    return res.format(**context)


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

    parser.add_argument("-o", "--out", type=str, help="output file", required=True)
    parser.add_argument("--aesKey", type=hexArg(16), help="VM aes cipher key (AES-128-CTR) (in hexa) (default: 0000000000000000", required=True)

    args = parser.parse_args()

    with open(args.out, 'w') as f:
        f.write(genHeader(args.aesKey))
