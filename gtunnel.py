#!/usr/bin/python
# -*- coding: utf-8 -*-

import functools
import struct

import gevent
import gevent.queue
import gevent.lock
import gevent.server
import gevent.socket


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


def read_bytes(sock, num_bytes):
    if num_bytes <= 0:
        return ''
    ret = ''
    while len(ret) < num_bytes:
        try:
            buf = sock.recv(num_bytes - len(ret))
        except gevent.socket.error:
            return ret
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
        self.tunnel_lock = gevent.lock.Semaphore()

        gevent.spawn(self.read_from_backend_and_put_to_queue)

        super(TunnelClient, self).__init__(*args, **kwargs)

    def read_from_backend_and_put_to_queue(self):
        while True:
            # close all tunnel
            for q in self.tunnels.itervalues():
                q.put('')

            if not self.backend or self.backend.closed:
                try:
                    self.backend = gevent.socket.create_connection(
                        self.backend_address)
                except gevent.socket.error:
                    break

            while True:
                header = read_bytes(self.backend, header_bit_format_size)
                if len(header) != header_bit_format_size:
                    self.backend.close()
                    break

                tunnel_id, body_size = struct.unpack(
                    header_bit_format, header)

                if body_size == 0:
                    if tunnel_id in self.tunnels:
                        self.tunnels[tunnel_id].put('')
                else:
                    encrypted_data = read_bytes(self.backend, body_size)
                    if len(encrypted_data) != body_size:
                        self.backend.close()
                        break
                    if tunnel_id in self.tunnels:
                        self.tunnels[tunnel_id].put(
                            self.crypto.decrypt(encrypted_data))
            # sleep for a while
            gevent.sleep(5)

    def get_from_queue_and_write_to_client(self, q, sock):
        while True:
            data = q.get()
            if not data:
                sock.close()
                break
            if sock.closed:
                break
            sock.sendall(data)


    def read_from_client_and_write_to_upstream(self, sock, tunnel_id):
        data = sock.recv(65536)
        if not data:
            return

        buf = []
        encrypted_data = self.crypto.encrypt(data)
        header = struct.pack(
            header_bit_format, tunnel_id, len(encrypted_data))
        buf.append(header)
        buf.append(encrypted_data)
        if sock.closed:
            close_header = struct.pack(header_bit_format, tunnel_id, 0)
            buf.append(close_header)
        if not self.backend or self.backend.closed:
            return
        self.backend.sendall(''.join(buf))


    def handle(self, sock, address):
        with self.tunnel_lock:
            self.tunnel_id += 1
            tunnel_id = self.tunnel_id
        q = gevent.queue.Queue()
        self.tunnels[tunnel_id] = q
        try:
            writer = gevent.spawn(
                self.get_from_queue_and_write_to_client, q, sock)
            self.read_from_client_and_write_to_upstream(sock, tunnel_id)
        finally:
            writer.kill()
            del self.tunnels[tunnel_id]


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
                sock.sendall(struct.pack(header_bit_format, tunnel_id, 0))
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
                backend.sendall(data)
            except gevent.queue.Empty:
                if sock.closed:
                    self.close_tunnel(tunnels, tunnel_id)
                    if not backend.closed:
                        backend.close()
                    break
                if not backend.closed and not tunnels[tunnel_id]['need_close']:
                    continue

                if backend.closed:
                    sock.sendall(struct.pack(
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
                sock.sendall(header + encrypted_data)
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
                        sock.sendall(
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
