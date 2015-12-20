#!/usr/bin/python
# -*- coding: utf-8 -*-

import gevent.server


class Client(gevent.server.StreamServer):
    pass


class Server(gevent.server.StreamServer):
    pass
