#!/usr/bin/env python

import camellia
import subprocess
import re

def check(test_file, key):

    p = subprocess.run([test_file], capture_output=True, check=True)

    m = bytes.fromhex(re.search(r'input: ([0-9a-f]{32})', p.stdout.decode('utf8')).group(1))
    output = bytes.fromhex(re.search(r'output: ([0-9a-f]{32})', p.stdout.decode('utf8')).group(1))

    c1 = camellia.CamelliaCipher(key=key, mode=camellia.MODE_ECB)
    expected = c1.encrypt(m)
    if output == expected:
        print('Test Success')
    else:
        print('Test Fail')
        print('Key: {}'.format(key.hex))
        print('Input: {}'.format(m.hex()))
        print('Expected: {}'.format(expected.hex()))
        print('Output: {}'.format(output.hex()))
        exit(1)


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

    parser.add_argument("-t", "--test-file", type=str, help="test executable", default="../build/test")
    parser.add_argument("-k", "--key", type=hexArg(16), help="VB Key", required=True)

    args = parser.parse_args()

    check(args.test_file, args.key)

