#!/usr/bin/env python3

import datetime
from hashlib import sha256
import os
import secrets
import struct
import subprocess
import sys
import tempfile
import time

SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.environ.get("OUT_DIR", os.path.abspath(os.path.dirname(SRC_DIR) + "/out"))

def build(suffix, mkey, outdir):

    print("{} begin build".format(datetime.datetime.now()), file=sys.stderr)
    ts = int(datetime.datetime.now().timestamp())
    ident = struct.pack('<I', ts)
    key = sha256(mkey + ident).digest()[:16]

    with tempfile.TemporaryDirectory() as builddir:
        subprocess.run(["cmake", SRC_DIR, "-G", "Ninja",
            "-DWB_SUFFIX={}".format(struct.pack('>Q', *struct.unpack('<Q', suffix)).hex()),
            "-DWB_KEY={}".format(key.hex()),
            "-DWB_ID={}".format(ident.hex()),
            "-DWB_AESENC_KEY={}".format(secrets.token_hex(16))],
            cwd=builddir, check=True)
        subprocess.run(["ninja", '-j', '1'], cwd=builddir, check=True)
        with open(builddir + "/libwblib.so", "rb") as f:
            whitebox_lib = f.read()

    fd, outfile = tempfile.mkstemp(prefix="libwblib-", suffix=".so", dir=outdir)
    with open(fd, 'wb') as f:
        f.write(whitebox_lib)

    os.chmod(outfile, 0o644)
    os.rename(outfile, outdir + "/libwblib.so")
    print("{} finish build".format(datetime.datetime.now()), file=sys.stderr)

def run(timer, suffix, key, outdir):

    while True:
        build(suffix, key, outdir)
        time.sleep(timer)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()

    class hexArg:

        def __init__(self, size):
            self.size = size

        def __call__(self, raw):
            try:
                b = bytes.fromhex(raw)
            except ValueError:
                raise argparse.ArgumentTypeError('Not an hexa value')

            if len(b) != self.size:
                raise argparse.ArgumentTypeError('Invalid lenght (need {} bytes)'.format(self.size))
            return b

    parser.add_argument("-o", "--out", type=str, help="output directory", default=OUT_DIR)
    parser.add_argument("-k", "--key", type=hexArg(16), help="whitebox master key (in hexa)", required=True)
    parser.add_argument("-t", "--timer", type=int, help="Duration between two generations", required=True)
    parser.add_argument("-s", "--suffix", type=hexArg(8), help="The 8 bytes of the suffix (in hexa)", required=True)

    args = parser.parse_args()

    run(args.timer, args.suffix, args.key, args.out)

