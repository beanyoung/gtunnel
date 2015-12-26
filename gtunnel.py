#!/usr/bin/python
# -*- coding: utf-8 -*-

import base64
import functools
import hashlib
import struct

import cryptography.fernet
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


@log_request
def read_bytes(sock, num_bytes):
    if num_bytes <= 0:
        return ''
    ret = ''
    while len(ret) < num_bytes:
        try:
            buf = sock.recv(num_bytes - len(ret))
        except gevent.socket.error:
            break
        if not buf:
            break
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

    @log_request
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
                    continue

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
                    if tunnel_id not in self.tunnels:
                        continue
                    self.tunnels[tunnel_id].put(
                        self.crypto.decrypt(encrypted_data))
            gevent.sleep(5)

    @log_request
    def get_from_queue_and_write_to_client(self, q, sock):
        while True:
            data = q.get()
            if not data:
                sock.close()
                break
            if sock.closed:
                break
            sock.sendall(data)

    @log_request
    def read_from_client_and_write_to_backend(self, sock, tunnel_id):
        # write -1 to backend
        open_header = struct.pack(header_bit_format, tunnel_id, -1)
        if not self.backend or self.backend.closed:
            return
        self.backend.sendall(open_header)

        while True:
            try:
                data = sock.recv(65536)
            except gevent.socket.error:
                break
            if not data:
                break

            buf = []
            encrypted_data = self.crypto.encrypt(data)
            header = struct.pack(
                header_bit_format, tunnel_id, len(encrypted_data))
            buf.append(header)
            buf.append(encrypted_data)
            if not self.backend or self.backend.closed:
                break
            self.backend.sendall(''.join(buf))

        close_header = struct.pack(header_bit_format, tunnel_id, 0)
        if self.backend and not self.backend.closed:
            self.backend.sendall(close_header)

    @log_request
    def handle(self, sock, address):
        if not self.backend or self.backend.closed:
            sock.close()
            return

        with self.tunnel_lock:
            self.tunnel_id += 1
            tunnel_id = self.tunnel_id
        q = gevent.queue.Queue()
        self.tunnels[tunnel_id] = q
        try:
            writer = gevent.spawn(
                self.get_from_queue_and_write_to_client, q, sock)
            self.read_from_client_and_write_to_backend(sock, tunnel_id)
        finally:
            writer.kill()
            writer.join()
            if not sock.closed:
                sock.close()
            self.tunnels.pop(tunnel_id, None)


class TunnelServer(gevent.server.StreamServer):
    def __init__(self, crypto, backend_address, *args, **kwargs):
        self.crypto = crypto
        self.backend_address = backend_address

        super(TunnelServer, self).__init__(*args, **kwargs)

    @log_request
    def handle(self, sock, adderss):
        tunnels = dict()
        while True:
            header = read_bytes(sock, header_bit_format_size)
            if len(header) != header_bit_format_size:
                break
            tunnel_id, body_size = struct.unpack(
                header_bit_format, header)
            if body_size == -1:
                q = gevent.queue.Queue()
                tunnels[tunnel_id] = q
                # TODO start thread
                gevent.spawn(
                    self.read_from_backend_and_write_to_client,
                    q,
                    tunnel_id,
                    sock,
                    lambda: tunnels.pop(tunnel_id, None)
                )
                continue
            if body_size == 0:
                if tunnel_id not in tunnels:
                    continue
                tunnels[tunnel_id].put('')
            else:
                encrypted_data = read_bytes(sock, body_size)
                if len(encrypted_data) != body_size:
                    break
                if tunnel_id not in tunnels:
                    continue
                tunnels[tunnel_id].put(self.crypto.decrypt(encrypted_data))

        for q in tunnels.itervalues():
            q.put('')

    @log_request
    def read_from_backend_and_write_to_client(
            self, q, tunnel_id, sock, finish_callback):
        try:
            backend = gevent.socket.create_connection(self.backend_address)
        except gevent.socket.error:
            close_header = struct.pack(header_bit_format, tunnel_id, 0)
            if not sock.closed:
                sock.sendall(close_header)
            return
        writer = gevent.spawn(
            self.get_from_queue_and_write_to_backend,
            q,
            backend)
        while True:
            try:
                data = backend.recv(65536)
            except gevent.socket.error:
                break
            if not data:
                break
            else:
                buf = []
                encrypted_data = self.crypto.encrypt(data)
                header = struct.pack(
                    header_bit_format, tunnel_id, len(encrypted_data))
                buf.append(header)
                buf.append(encrypted_data)
                if sock.closed:
                    break
                sock.sendall(''.join(buf))
        writer.kill()
        writer.join()
        if not backend.closed:
            backend.close()
        close_header = struct.pack(header_bit_format, tunnel_id, 0)
        if not sock.closed:
            sock.sendall(close_header)
        finish_callback()

    @log_request
    def get_from_queue_and_write_to_backend(self, q, backend):
        while True:
            data = q.get()
            if not data:
                backend.close()
                break
            if backend.closed:
                break
            backend.sendall(data)


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

    crypto = cryptography.fernet.Fernet(
        base64.urlsafe_b64encode(hashlib.md5(args.secret).hexdigest()))

    if args.client_mode:
        server = TunnelClient(
            crypto, backend_address, ('0.0.0.0', args.listen))
        server.serve_forever()
    else:
        server = TunnelServer(
            crypto, backend_address, ('0.0.0.0', args.listen))
        server.serve_forever()
