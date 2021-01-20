#!/usr/bin/env python

import socket
import struct

UDPPort = 65431
Host = socket.gethostbyname("surbayrole.fr")

Ident = 1


def oracle(cipher, host=Host, port=UDPPort):

    if type(cipher) is not bytes or len(cipher) != 16:
        return None

    msg = struct.pack('!I', Ident)
    msg += cipher

    UDPSock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    UDPSock.sendto(msg, (host, port))
    answer, _ = UDPSock.recvfrom(16)

    UDPSock.close()

    if len(answer) != 16:
        return None

    return answer


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

    parser.add_argument("--host", "-H", type=str, help="Oracle ip address", default=Host)
    parser.add_argument("--port", "-p", type=int, help="Oracle udp port", default=UDPPort)
    parser.add_argument('cipher', type=hexArg(16), help='message to decipher')

    args = parser.parse_args()

    plain = oracle(args.cipher, host=args.host, port=args.port)
    if plain is not None:
        print(plain.hex())
    else:
        print('Error')
