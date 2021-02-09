#!/usr/bin/env python

import camellia
import datetime
from enum import IntEnum, unique
from key_decode import VM_decode, VM_EXPIRE
import multiprocessing as mp
import socket
import struct
import time
import traceback

Port = 65430
Host = "0.0.0.0"

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
    REQUEST_ERROR = 0xfe
    UNEXPECTED_ERROR = 0xff

def reqCheck(sock, address, m):
    if len(m) < 21:
        print("reqCheck REQUEST_ERROR")
        sock.send(bytes([RespType.REQUEST_ERROR.value]))
        return

    payload = m[1:21]
    ts = struct.unpack('<I', payload[16:])[0]
    current_ts = int(datetime.datetime.now().timestamp())

    plain = VM_decode(payload)

    if plain == None:
        print("reqCheck UNEXPECTED_ERROR")
        sock.send(bytes([RespType.UNEXPECTED_ERROR.value]))
    elif ts + VM_EXPIRE > current_ts:
        print("reqCheck CHECK_OK")
        sock.send(bytes([RespType.CHECK_OK.value]) + plain)
    else:
        print("reqCheck CHECK_EXPIRED")
        sock.send(bytes([RespType.CHECK_EXPIRED.value]) + plain)
    return


def process_main(sock, address):
    m = sock.recv(512)
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
        sock.close()
        return

    if reqType == ReqType.CHECK:
        reqCheck(sock, address, m)
    #elif reqType == ReqType.GETKEY:
    #    pass
    else:
        print("process_main REQUEST_ERROR no handler for reqType {}".format(reqType))
        sock.send(bytes([RespType.REQUEST_ERROR.value]))
    sock.close()

def worker(sock):
    cont = True
    while cont:
        client = None
        try:
            client, address = sock.accept()
            process_main(client, address)
        except KeyboardInterrupt:
            cont = False
        except Exception as e:
            traceback.print_exc()
        if client != None:
            client.close()

def main():
    n_worker = 1

    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((Host, Port))
    sock.listen(8 * n_worker)

    workers = [mp.Process(target=worker, args=(sock,), daemon=True) for i in range(n_worker)]

    for w in workers:
        w.start()

    while True:
        for i in range(len(workers)):
            workers[i].join(0.001)
            if workers[i].exitcode != None:
                workers[i] = mp.Process(target=worker, args=(sock,), daemon=True)
                workers[i].start()
        time.sleep(1)

if __name__ == '__main__':
    main()
