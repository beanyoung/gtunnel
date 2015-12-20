#!/usr/bin/python
# -*- coding: utf-8 -*-

import struct

import gevent
import gevent.server
import gevent.socket


header_bit_format = '!QI'
header_bit_format_size = struct.calcsize(header_bit_format)


def read_bytes(sock, size):
    print sock.closed, size
    if size <= 0:
        return ''
    ret = ''
    while len(ret) < size:
        print 'recv', size - len(ret)
        buf = sock.recv(size - len(ret))
        if not buf:
            print 'read_bytes return', ret
            return ret
        ret += buf
    print 'read_bytes return', ret
    return ret


class Crypto(object):
    def __init__(self, secret):
        pass

    def encrypt(self, data):
        return data

    def decrypt(self, data):
        return data


class TunnelClient(gevent.server.StreamServer):
    def __init__(self, crypto, backend_address, *args, **kwargs):
        self.crypto = crypto
        self.backend_address = backend_address
        self.backend = None

        self.tunnels = dict()
        self.tunnel_id = 0

        gevent.spawn(self.connect_to_backend)

        super(TunnelClient, self).__init__(*args, **kwargs)

    def connect_to_backend(self):
        while True:
            try:
                print self.backend
                if not self.backend or self.backend.closed:
                    self.backend = gevent.socket.create_connection(
                        self.backend_address, 10)
                while True:
                    header = read_bytes(self.backend, header_bit_format_size)
                    if len(header) != header_bit_format_size:
                        self.backend.close()
                        self.close_all_tunnels()
                        break
                    tunnel_id, body_size = struct.unpack(
                        header_bit_format, header)
                    if body_size == 0:
                        self.close_tunnel(tunnel_id)
                    else:
                        encrypted_data = read_bytes(self.backend, body_size)
                        if len(encrypted_data) != body_size:
                            self.backend.close()
                            self.close_all_tunnels()
                            break
                        if tunnel_id in self.tunnels:
                            self.tunnels[tunnel_id].send(
                                self.crypto.decrypt(encrypted_data))
            except Exception as e:
                print 'connect_to_backend error', e
            finally:
                if self.backend and self.backend.closed:
                    self.close_all_tunnels()

    def open_tunnel(self, sock):
        self.tunnel_id += 1
        tunnel_id = self.tunnel_id
        self.tunnels[tunnel_id] = sock
        return tunnel_id

    def close_tunnel(self, tunnel_id):
        if tunnel_id in self.tunnels:
            if not self.tunnels[tunnel_id].closed:
                self.tunnels[tunnel_id].close()
            if self.backend and not self.backend.closed:
                self.backend.send(struct.pack(header_bit_format, tunnel_id, 0))
            self.tunnels.pop(tunnel_id)

    def close_all_tunnels(self):
        for sock in self.tunnels.itervalues():
            if not sock.closed:
                sock.close()
        self.tunnels = dict()

    def handle(self, sock, address):
        if not self.backend or self.backend.closed:
            sock.close()
            return
        tunnel_id = self.open_tunnel(sock)

        try:
            while True:
                if sock.closed():
                    self.close_tunnel(tunnel_id)
                    break
                if not self.backend or self.backend.closed:
                    break
                data = sock.recv(65536)
                if data:
                    encrypted_data = self.crypto.encrypt(data)
                    header = struct.pack(
                        header_bit_format, tunnel_id, len(encrypted_data))
                    self.backend.send(header + encrypted_data)
                else:
                    break
        except Exception as e:
            print 'handle error', e
        finally:
            self.close_tunnel(tunnel_id)


class TunnelServer(gevent.server.StreamServer):
    def __init__(self, crypto, backend_address, *args, **kwargs):
        self.crypto = crypto
        # TODO
        self.backend_address = backend_address
        self.backend = None

        self.tunnels = dict()
        super(TunnelServer, self).__init__(*args, **kwargs)

    # TODO
    def handle(self, sock, address):
        while True:
            try:
                while True:
                    header = read_bytes(sock, header_bit_format_size)
                    if len(header) != header_bit_format_size:
                        self.close_all_tunnels()
                        break
                    tunnel_id, body_size = struct.unpack(
                        header_bit_format, header)
                    if body_size == 0:
                        self.close_tunnel(tunnel_id)
                    else:
                        encrypted_data = read_bytes(self.backend, body_size)
                        if len(encrypted_data) != body_size:
                            self.close_all_tunnels()
                            break
                        self.open_tunnel(
                            tunnel_id, self.crypto.decrypt(encrypted_data))
            except Exception as e:
                pass
            finally:
                if not sock.closed:
                    continue
                self.close_all_tunnels()
                break

    def open_tunnel(self, tunnel_id, data):
        pass

    def close_tunnel(self, tunnel_id):
        pass

    def close_all_tunnels(self):
        self.tunnels = dict()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Running gtunnel')
    parser.add_argument(
        '-b', '--backend', type=str, required=True,
        help='backend address', dest='backend')
    parser.add_argument(
        '-c', '--client-mode', type=int, required=True,
        help='running in client mode', dest='client_mode')
    parser.add_argument(
        '-l', '--listen', type=int, required=True,
        help='listen port', dest='listen')
    parser.add_argument(
        '-s', '--secret', type=str, required=True,
        help='secret key', dest='secret')

    args = parser.parse_args()
    backend_address = (args.backend.split(':')[0],
                       int(args.backend.split(':')[1]))

    crypto = Crypto(args.secret)

    if args.client_mode:
        server = TunnelClient(
            crypto, backend_address, ('0.0.0.0', args.listen))
        server.serve_forever()
    else:
        server = TunnelServer(
            crypto, backend_address, ('0.0.0.0', args.listen))
        server.serve_forever()
