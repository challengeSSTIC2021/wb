#!/usr/bin/env python

import camellia
import datetime
from enum import IntEnum, unique
from hashlib import sha256
import json
import os
import multiprocessing as mp
import socket
import struct
import time
import traceback

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

def VM_decode(payload, master_key):
    if type(payload) != bytes or len(payload) != 20:
        return None

    cipher = payload[:16]
    ident = payload[16:]

    key = sha256(master_key + ident).digest()[:16]

    c1 = camellia.CamelliaCipher(key=key, mode=camellia.MODE_ECB)
    return c1.decrypt(cipher)


def reqCheck(sock, address, ctx):
    payload = sock.recv(20)
    if len(payload) != 20:
        print("reqCheck REQUEST_ERROR")
        sock.send(bytes([RespType.REQUEST_ERROR.value]))
        return

    ts = struct.unpack('<I', payload[16:])[0]
    current_ts = int(datetime.datetime.now().timestamp())

    plain = VM_decode(payload, ctx["master-key"])

    if plain == None:
        print("reqCheck UNEXPECTED_ERROR")
        sock.send(bytes([RespType.UNEXPECTED_ERROR.value]))
    elif ts + ctx["timeout"] > current_ts:
        print("reqCheck CHECK_OK")
        sock.send(bytes([RespType.CHECK_OK.value]) + plain)
    else:
        print("reqCheck CHECK_EXPIRED")
        sock.send(bytes([RespType.CHECK_EXPIRED.value]) + plain)
    return

def reqGetKey(sock, address, ctx):
    payload = sock.recv(20)
    if len(payload) != 20:
        print("reqGetKey REQUEST_ERROR")
        sock.send(bytes([RespType.REQUEST_ERROR.value]))
        return

    ts = struct.unpack('<I', payload[16:])[0]
    current_ts = int(datetime.datetime.now().timestamp())

    # whitebox expired
    if ts + ctx["timeout"] <= current_ts:
        print("reqGetKey GETKEY_EXPIRED")
        sock.send(bytes([RespType.GETKEY_EXPIRED.value]))
        return

    plain = VM_decode(payload, ctx["master-key"])
    if plain == None or len(plain) != 16:
        print("reqGetKey UNEXPECTED_ERROR")
        sock.send(bytes([RespType.UNEXPECTED_ERROR.value]))
        return

    ident, perm = struct.unpack('<QQ', plain)

    if ((ident >> 63) & 1) != 0 and not ctx["prod"]:
        print("reqGetKey GETKEY_DEBUG_DEVICE")
        sock.send(bytes([RespType.GETKEY_DEBUG_DEVICE.value]))
        return

    if ident not in ctx["keys"]:
        print("reqGetKey GETKEY_UNKNOW")
        sock.send(bytes([RespType.GETKEY_UNKNOW.value]))
        return

    if ctx["keys"][ident]["perms"] < perm:
        print("reqGetKey GETKEY_INVALID_PERMS")
        sock.send(bytes([RespType.GETKEY_INVALID_PERMS.value]))
        return

    print("reqGetKey GETKEY_OK {} with perm {}".format(ident, perm))
    sock.send(bytes([RespType.GETKEY_OK.value]) + bytes.fromhex(ctx["keys"][ident]["key"]))

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

    parser.add_argument("-K", "--master-key", type=hexArg(), help="whitebox master key", required=True)
    parser.add_argument("-t", "--timeout", type=int, help="whitebox expired", required=True)
    parser.add_argument("-k", "--key-file", type=str, help="key files", default="keys.json")
    parser.add_argument("-w", "--workers", type=int, help="worker", default=16)
    parser.add_argument("-l", "--listen-port", type=int, help="listening port", default=65430)
    parser.add_argument("-p", "--prod", action='store_true')

    args = parser.parse_args()

    if not os.path.isfile(args.key_file):
        parser.error('Cannot found {}'.format(args.key_file))

    with open(args.key_file, 'r') as f:
        jkeys = json.loads(f.read())
    keys = {}
    for j in jkeys:
        keys[j['ident']] = j

    context = {
        "keys": keys,
        "master-key": args.master_key,
        "timeout": args.timeout,
        "prod": args.prod
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
