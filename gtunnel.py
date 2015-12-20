#!/usr/bin/python
# -*- coding: utf-8 -*-

import functools
import struct

import gevent
import gevent.queue
import gevent.server
import gevent.socket


# default_timeout = 100
default_timeout = 3
header_bit_format = '!Qi'
header_bit_format_size = struct.calcsize(header_bit_format)


def log_request(f):
    @functools.wraps(f)
    def decorator(*args, **kwargs):
        print f.func_name, 'start'
        ret = f(*args, **kwargs)
        print f.func_name, 'end'
        return ret
    return decorator


@log_request
def read_bytes(sock, size):
    if size <= 0:
        return ''
    ret = ''
    while len(ret) < size:
        try:
            buf = sock.recv(size - len(ret))
        except gevent.socket.timeout as e:
            continue
        if not buf:
            return ret
        ret += buf
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

    @log_request
    def connect_to_backend(self):
        while True:
            try:
                if not self.backend or self.backend.closed:
                    print '1'
                    self.backend = gevent.socket.create_connection(
                        self.backend_address, default_timeout)
                while True:
                    print '2'
                    header = read_bytes(self.backend, header_bit_format_size)
                    if len(header) != header_bit_format_size:
                        self.backend.close()
                        self.close_all_tunnels()
                        break
                    tunnel_id, body_size = struct.unpack(
                        header_bit_format, header)
                    print 'read from backend', tunnel_id, body_size
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
                print 'here'
                if self.backend and self.backend.closed:
                    self.close_all_tunnels()

    @log_request
    def open_tunnel(self, sock):
        self.tunnel_id += 1
        tunnel_id = self.tunnel_id
        self.tunnels[tunnel_id] = sock
        return tunnel_id

    @log_request
    def close_tunnel(self, tunnel_id):
        if tunnel_id in self.tunnels:
            if not self.tunnels[tunnel_id].closed:
                self.tunnels[tunnel_id].close()
            if self.backend and not self.backend.closed:
                self.backend.send(struct.pack(header_bit_format, tunnel_id, 0))
            self.tunnels.pop(tunnel_id)

    @log_request
    def close_all_tunnels(self):
        for sock in self.tunnels.itervalues():
            if not sock.closed:
                sock.close()
        self.tunnels = dict()

    @log_request
    def handle(self, sock, address):
        if not self.backend or self.backend.closed:
            sock.close()
            return
        try:
            tunnel_id = self.open_tunnel(sock)
            header = struct.pack(header_bit_format, tunnel_id, -1)
            self.backend.send(header)
            while True:
                print 'while'
                if sock.closed:
                    self.close_tunnel(tunnel_id)
                    break
                if not self.backend or self.backend.closed:
                    break
                data = sock.recv(65536)
                if data:
                    encrypted_data = self.crypto.encrypt(data)
                    header = struct.pack(
                        header_bit_format, tunnel_id, len(encrypted_data))
                    print 'send', tunnel_id, len(encrypted_data)
                    self.backend.send(header + encrypted_data)
                else:
                    self.close_tunnel(tunnel_id)
                    break
        except Exception as e:
            print 'handle error', e
        finally:
            self.close_tunnel(tunnel_id)


class TunnelServer(gevent.server.StreamServer):
    def __init__(self, crypto, backend_address, *args, **kwargs):
        self.crypto = crypto
        self.backend_address = backend_address

        super(TunnelServer, self).__init__(*args, **kwargs)

    @log_request
    def open_tunnel(self, sock, tunnels, tunnel_id):
        try:
            backend = gevent.socket.create_connection(
                self.backend_address, default_timeout)
        except Exception as e:
            print 'open_tunnel error', e
            if not sock.closed:
                sock.send(struct.pack(header_bit_format, tunnel_id, 0))
            self.close_tunnel(tunnels, tunnel_id)
            return
        gevent.spawn(
            self.read_from_backend_until_close,
            backend,
            sock,
            tunnels,
            tunnel_id)
        while True:
            try:
                data = tunnels[tunnel_id]['queue'].get(timeout=default_timeout)
                print 'write to backend', tunnel_id, len(data)
                backend.send(data)
            except gevent.queue.Empty:
                if sock.closed:
                    self.close_tunnel(tunnels, tunnel_id)
                    if not backend.closed:
                        backend.close()
                    break
                if not backend.closed and not tunnels[tunnel_id]['need_close']:
                    continue

                if backend.closed:
                    sock.send(struct.pack(
                        header_bit_format_size, tunnel_id, 0))
                    self.close_tunnel(tunnels, tunnel_id)
                    break
                if tunnels[tunnel_id]['need_close']:
                    self.close_tunnel(tunnels, tunnel_id)
                    backend.close()
                    break
            except Exception as e:
                print 'open_tunnel error 1', e
                break

    @log_request
    def read_from_backend_until_close(self, backend, sock, tunnels, tunnel_id):
        while True:
            try:
                data = backend.recv(65536)
            except gevent.socket.timeout:
                continue
            except gevent.socket.error:
                break
            if data:
                encrypted_data = self.crypto.encrypt(data)
                header = struct.pack(
                    header_bit_format, tunnel_id, len(encrypted_data))
                sock.send(header + encrypted_data)
            else:
                break

    @log_request
    def close_tunnel(self, tunnels, tunnel_id):
        tunnels.pop(tunnel_id)

    # TODO
    @log_request
    def handle(self, sock, address):
        tunnels = dict()
        while True:
            try:
                header = read_bytes(sock, header_bit_format_size)
                if len(header) != header_bit_format_size:
                    break
                tunnel_id, body_size = struct.unpack(
                    header_bit_format, header)
                print tunnel_id, body_size
                if body_size == 0 and tunnel_id in tunnels:
                    tunnels[tunnel_id]['need_close'] = True
                elif body_size == -1:
                    tunnels[tunnel_id] = dict(
                        queue=gevent.queue.Queue(),
                        need_close=False
                    )
                    gevent.spawn(
                        self.open_tunnel, sock, tunnels, tunnel_id)
                else:
                    encrypted_data = read_bytes(sock, body_size)
                    if len(encrypted_data) != body_size:
                        sock.close()
                        break
                    if tunnel_id in tunnels:
                        tunnels[tunnel_id]['queue'].put(
                            self.crypto.decrypt(encrypted_data))
                    else:
                        sock.send(
                            struct.pack(header_bit_format, tunnel_id, 0))
            except Exception as e:
                print 'handle error', e
                break
        if not sock.closed:
            sock.close()


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
