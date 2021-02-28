#!/usr/bin/env python

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

@unique
class ReqType(IntEnum):
    CHECK = 0
    GETKEY = 1

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
    REQUEST_ERROR = 0xfe
    UNEXPECTED_ERROR = 0xff

def getResp(ctx):
    res = ctx['rsock'].recv(1)

    try:
        respType = RespType(int(res[0]))
    except ValueError:
        print("reqCheck unknown respType : {}".format(int(respType)))
        sock.send(bytes([RespType.REQUEST_ERROR.value]))
        return None, res

    if respType in [RespType.CHECK_OK, RespType.CHECK_EXPIRED, RespType.GETKEY_OK]:
        res += ctx['rsock'].recv(16)
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

def reqCheck(sock, address, ctx):
    payload = sock.recv(20)
    if len(payload) != 20:
        print("reqCheck REQUEST_ERROR")
        sock.send(bytes([RespType.REQUEST_ERROR.value]))
        return

    print("CHECK request payload:{} ident:{}".format(payload[:16].hex(), payload[16:].hex()))

    with ctx['lock']:
        m = bytes([ReqType.CHECK.value]) + payload
        ctx['rsock'].send(m)

        respType, res = getResp(ctx)

    sock.send(res)
    print("{}: {}".format(respType, res[1:].hex()))
    return

def reqGetKey(sock, address, ctx):
    payload = sock.recv(20)
    if len(payload) != 20:
        print("reqGetKey REQUEST_ERROR")
        sock.send(bytes([RespType.REQUEST_ERROR.value]))
        return

    print("GETKEY request payload:{} ident:{}".format(payload[:16].hex(), payload[16:].hex()))

    with ctx['lock']:
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

            m = bytes([ReqType.GETKEY.value]) + cipher + payload[16:]
            ctx['rsock'].send(m)

            respType, res = getResp(ctx)

    sock.send(res)
    print("{}: {}".format(respType, res[1:].hex()))
    return

def process_main(sock, address, ctx):
    try:
        print("Begin connexion {}".format(address))
        sock.send(b'STIC');
        while True:
            m = sock.recv(1)
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

            if reqType == ReqType.CHECK:
                reqCheck(sock, address, ctx)
            elif reqType == ReqType.GETKEY:
                reqGetKey(sock, address, ctx)
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

    parser.add_argument("-W", "--workers", type=int, help="worker", default=4)
    parser.add_argument("-l", "--listen-port", type=int, help="listening port", default=65430)
    parser.add_argument("-a", "--remote-address", type=str, default="127.0.0.1")
    parser.add_argument("-p", "--remote-port", type=int, default=1337)
    parser.add_argument("-w", "--wb-address", type=str, default='http://127.0.0.1:8080/api/guest.so')

    args = parser.parse_args()

    rsock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    rsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rsock.connect((args.remote_address, args.remote_port))

    print("connected to {}:{}".format(args.remote_address, args.remote_port))

    header = rsock.recv(4)

    if header != b'STIC':
        print("Fail recevied header: exit")
        os.exit(1)
    print("connection ready")

    context = {
        "lock": mp.Lock(),
        "rsock": rsock,
        "wb_address": args.wb_address,
        "solver": None,
    }

    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", args.listen_port))
    sock.listen(8 * args.workers)

    workers = [mp.Process(target=worker, args=(sock, context), daemon=True) for i in range(args.workers)]

    for w in workers:
        w.start()

    while True:
        for i in range(len(workers)):
            workers[i].join(0.001)
            if workers[i].exitcode != None:
                workers[i] = mp.Process(target=worker, args=(sock, context), daemon=True)
                workers[i].start()
        time.sleep(1)

if __name__ == '__main__':
    main()
