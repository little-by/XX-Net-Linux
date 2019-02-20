#!/usr/bin/env python
# coding:utf-8
import os
import urlparse
import datetime
import threading
import mimetools
import socket
import errno
import sys
import select
import time
import base64
import hashlib
import struct

from logger import logger


class GetReqTimeout(Exception):
    pass


class HttpServerHandler():
    WebSocket_MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    default_request_version = "HTTP/1.1"
    MessageClass = mimetools.Message
    rbufsize = -1
    wbufsize = 0

    def __init__(self, sock, client, args, logger=None):
        self.connection = sock
        sock.setblocking(1)
        sock.settimeout(60)
        self.rfile = socket._fileobject(self.connection, "rb", self.rbufsize, close=True)
        self.wfile = socket._fileobject(self.connection, "wb", self.wbufsize, close=True)
        self.client_address = client
        self.args = args
        self.logger = logger
        self.setup()

    def setup(self):
        pass

    def __del__(self):
        try:
            socket.socket.close(self.connection)
        except:
            pass

    def handle(self):
        #self.logger.info('Connected from %r', self.client_address)
        while True:
            try:
                self.close_connection = 1
                self.handle_one_request()
            except Exception as e:
                #self.logger.warn("handle err:%r close", e)
                self.close_connection = 1

            if self.close_connection:
                break
        self.connection.close()
        #self.logger.debug("closed from %s:%d", self.client_address[0], self.client_address[1])

    def address_string(self):
        return '%s:%s' % self.client_address[:2]

    def parse_request(self):
        try:
            self.raw_requestline = self.rfile.readline(65537)
        except:
            raise GetReqTimeout()

        if not self.raw_requestline:
            raise GetReqTimeout()

        if len(self.raw_requestline) > 65536:
            raise ParseReqFail("Recv command line too large")

        if self.raw_requestline[0] == '\x16':
            raise socket.error

        self.command = None  # set in case of error on the first line
        self.request_version = version = self.default_request_version

        requestline = self.raw_requestline
        requestline = requestline.rstrip('\r\n')
        self.requestline = requestline
        words = requestline.split()
        if len(words) == 3:
            command, path, version = words
            if version[:5] != 'HTTP/':
                raise ParseReqFail("Req command format fail:%s" % requestline)

            try:
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                # RFC 2145 section 3.1 says there can be only one "." and
                #   - major and minor numbers MUST be treated as
                #      separate integers;
                #   - HTTP/2.4 is a lower version than HTTP/2.13, which in
                #      turn is lower than HTTP/12.3;
                #   - Leading zeros MUST be ignored by recipients.
                if len(version_number) != 2:
                    raise ParseReqFail("Req command format fail:%s" % requestline)
                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                raise ParseReqFail("Req command format fail:%s" % requestline)
            if version_number >= (1, 1):
                self.close_connection = 0
            if version_number >= (2, 0):
                raise ParseReqFail("Req command format fail:%s" % requestline)
        elif len(words) == 2:
            command, path = words
            self.close_connection = 1
            if command != 'GET':
                raise ParseReqFail("Req command format HTTP/0.9 line:%s" % requestline)
        elif not words:
            raise ParseReqFail("Req command format fail:%s" % requestline)
        else:
            raise ParseReqFail("Req command format fail:%s" % requestline)
        self.command, self.path, self.request_version = command, path, version

        # Examine the headers and look for a Connection directive
        self.headers = self.MessageClass(self.rfile, 0)

        self.host = self.headers.get('Host', "")
        conntype = self.headers.get('Connection', "")
        if conntype.lower() == 'close':
            self.close_connection = 1
        elif conntype.lower() == 'keep-alive':
            self.close_connection = 0

        self.upgrade = self.headers.get('Upgrade', "").lower()

        return True

    def handle_one_request(self):
        try:
            self.parse_request()

            self.close_connection = 0

            if self.upgrade == "websocket":
                self.do_WebSocket()
            elif self.command == "GET":
                self.do_GET()
            elif self.command == "POST":
                self.do_POST()
            elif self.command == "CONNECT":
                self.do_CONNECT()
            elif self.command == "HEAD":
                self.do_HEAD()
            elif self.command == "DELETE":
                self.do_DELETE()
            elif self.command == "OPTIONS":
                self.do_OPTIONS()
            elif self.command == "PUT":
                self.do_PUT()
            else:
                self.logger.warn("unhandler cmd:%s path:%s from:%s", self.command, self.path, self.address_string())
                return

            self.wfile.flush() #actually send the response if not already done.

        except socket.error as e:
            #self.logger.warn("socket error:%r", e)
            self.close_connection = 1
        except IOError as e:
            if e.errno == errno.EPIPE:
                self.logger.warn("PIPE error:%r", e)
                pass
            else:
                self.logger.warn("IOError:%r", e)
                pass
        #except OpenSSL.SSL.SysCallError as e:
        #    self.logger.warn("socket error:%r", e)
            self.close_connection = 1
        except GetReqTimeout:
            self.close_connection = 1
        except Exception as e:
            self.logger.exception("handler:%r cmd:%s path:%s from:%s", e,  self.command, self.path, self.address_string())
            self.close_connection = 1


class HTTPServer():
    def __init__(self, address, handler, args=(), use_https=False, cert="", logger=logger):
        self.sockets = []
        self.running = True
        if isinstance(address, tuple):
            self.server_address = [address]
        else:
            # server can listen multi-port
            self.server_address = address
        self.handler = handler
        self.logger = logger
        self.args = args
        self.use_https = use_https
        self.cert = cert
        self.init_socket()
        
    def init_socket(self):
        server_address = set(self.server_address)
        ips = [ip for ip, _ in server_address]
        listen_all_v4 = "0.0.0.0" in ips
        listen_all_v6 = "::" in ips
        for ip, port in server_address:
            if ip not in ("0.0.0.0", "::") and (
                    listen_all_v4 and '.' in ip or
                    listen_all_v6 and ':' in ip):
                continue
            self.add_listen((ip, port))

    def add_listen(self, addr):
        if ":" in addr[0]:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        addr = tuple(addr)
        try:
            sock.bind(addr)
        except Exception as e:
            err_string = "bind to %s:%d fail:%r" % (addr[0], addr[1], e)
            self.logger.error(err_string)
            raise Exception(err_string)

        if self.use_https:
            import OpenSSL
            if hasattr(OpenSSL.SSL, "TLSv1_2_METHOD"):
                ssl_version = OpenSSL.SSL.TLSv1_2_METHOD
            elif hasattr(OpenSSL.SSL, "TLSv1_1_METHOD"):
                ssl_version = OpenSSL.SSL.TLSv1_1_METHOD
            elif hasattr(OpenSSL.SSL, "TLSv1_METHOD"):
                ssl_version = OpenSSL.SSL.TLSv1_METHOD

            ctx = OpenSSL.SSL.Context(ssl_version)
            # server.pem's location (containing the server private key and the server certificate).
            fpem = self.cert
            ctx.use_privatekey_file(fpem)
            ctx.use_certificate_file(fpem)
            sock = OpenSSL.SSL.Connection(ctx, sock)
        sock.listen(200)
        self.sockets.append(sock)
        self.logger.info("server %s:%d started.", addr[0], addr[1])

    def dopoll(self, poller):
        while True:
            try:
                return poller.poll()
            except IOError as e:
                if e.errno != 4:  # EINTR:
                    raise

    def serve_forever(self):
        if hasattr(select, 'epoll'):

            fn_map = {}
            p = select.epoll()
            for sock in self.sockets:
                fn = sock.fileno()
                sock.setblocking(0)
                p.register(fn, select.EPOLLIN | select.EPOLLHUP | select.EPOLLPRI)
                fn_map[fn] = sock

            while self.running:
                try:
                    events = p.poll(timeout=1)
                except IOError as e:
                    if e.errno != 4:  # EINTR:
                        raise
                    else:
                        time.sleep(1)
                        continue

                for fn, event in events:
                    if fn not in fn_map:
                        self.logger.error("p.poll get fn:%d", fn)
                        continue

                    sock = fn_map[fn]
                    try:
                        (sock, address) = sock.accept()
                    except IOError as e:
                        if e.args[0] == 11:
                            # Resource temporarily unavailable is EAGAIN
                            # and that's not really an error.
                            # It means "I don't have answer for you right now and
                            # you have told me not to wait,
                            # so here I am returning without answer."
                            continue

                        if e.args[0] == 24:
                            self.logger.warn("max file opened when sock.accept")
                            time.sleep(30)
                            continue

                        self.logger.warn("socket accept fail(errno: %s).", e.args[0])
                        continue

                    try:
                        self.process_connect(sock, address)
                    except Exception as e:
                        self.logger.exception("process connect error:%r", e)

        else:
            while self.running:
                r, w, e = select.select(self.sockets, [], [], 1)
                for rsock in r:
                    try:
                        (sock, address) = rsock.accept()
                    except IOError as e:
                        self.logger.warn("socket accept fail(errno: %s).", e.args[0])
                        if e.args[0] == 10022:
                            self.logger.info("restart socket server.")
                            self.close_all_socket()
                            self.init_socket()
                        break

                    self.process_connect(sock, address)
        self.server_close()

    def process_connect(self, sock, address):
        #self.logger.debug("connect from %s:%d", address[0], address[1])
        client_obj = self.handler(sock, address, self.args)
        client_thread = threading.Thread(target=client_obj.handle)
        client_thread.start()

    def shutdown(self):
        self.running = False
        self.server_close()

    def server_close(self):
        for sock in self.sockets:
            sock.close()
        self.sockets = []
