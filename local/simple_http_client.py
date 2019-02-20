#!/usr/bin/env python2
# coding:utf-8
import select
import urlparse
import socket
import httplib
import time
import Queue
import os
import errno
import logging
import ssl


class BaseResponse(object):
    def __init__(self, status=601, reason="", headers={}, body=""):
        self.status = status
        self.reason = reason
        self.headers = {}
        for key in headers:
            if isinstance(key, tuple):
                key, value = key
            else:
                value = headers[key]
            key = str(key.title())
            self.headers[key] = value

        self.text = body

    def getheader(self, key, default_value=""):
        key = key.title()
        if key in self.headers:
            return self.headers[key]
        else:
            return default_value


class Response(BaseResponse):
    def __init__(self, ssl_sock):
        BaseResponse.__init__(self)
        self.connection = ssl_sock
        ssl_sock.settimeout(1)
        self.read_buffer = ""
        self.buffer_start = 0
        self.chunked = False

    def read_line(self, timeout=60):
        start_time = time.time()
        sock = self.connection
        sock.setblocking(0)
        try:
            while True:
                n1 = self.read_buffer.find("\r\n", self.buffer_start)
                if n1 > -1:
                    line = self.read_buffer[self.buffer_start:n1]
                    self.buffer_start = n1 + 2
                    return line

                if time.time() - start_time > timeout:
                    raise Exception("time out")
                time.sleep(0.001)
                try:
                    data = sock.recv(8192)
                except socket.error as e:
                    # logging.exception("e:%r", e)
                    if e.errno in [2, 11, 10035]:
                        #time.sleep(0.1)
                        time_left = start_time + timeout - time.time()
                        r, w, e = select.select([sock], [], [], time_left)
                        continue
                    else:
                        raise e

                if isinstance(data, int):
                    continue
                self.read_buffer += data
        finally:
            sock.setblocking(1)

    def read_headers(self, timeout=60):
        start_time = time.time()
        sock = self.connection
        sock.setblocking(0)
        try:
            while True:
                n1 = self.read_buffer.find("\r\n\r\n", self.buffer_start)
                if n1 > -1:
                    block = self.read_buffer[self.buffer_start:n1]
                    self.buffer_start = n1 + 4
                    return block

                if time.time() - start_time > timeout:
                    raise Exception("time out")

                time.sleep(0.001)
                try:
                    data = sock.recv(8192)
                except socket.error as e:
                    # logging.exception("e:%r", e)
                    if e.errno in [2, 11, 10035]:
                        time.sleep(0.1)
                        continue
                    else:
                        raise e

                self.read_buffer += data
        finally:
            sock.setblocking(1)

    def begin(self, timeout=60):
        start_time = time.time()
        line = self.read_line(timeout)

        requestline = line.rstrip('\r\n')
        words = requestline.split()
        if len(words) < 2:
            raise Exception("status line:%s" % requestline)

        self.version = words[0]
        self.status = int(words[1])
        self.reason = " ".join(words[2:])

        self.headers = {}
        timeout -= time.time() - start_time
        timeout = max(timeout, 0.1)
        header_block = self.read_headers(timeout)
        lines = header_block.split("\r\n")
        for line in lines:
            p = line.find(":")
            key = line[0:p]
            value = line[p+2:]
            key = str(key.title())
            self.headers[key] = value

        self.content_length = self.getheader("content-length", None)


class Client(object):
    def __init__(self, proxy=None, timeout=60, cert=""):
        self.timeout = timeout
        self.cert = cert

        if isinstance(proxy, str):
            proxy_sp = urlparse.urlsplit(proxy)

            self.proxy = {
                "type": proxy_sp.scheme,
                "host": proxy_sp.hostname,
                "port": proxy_sp.port,
                "user": proxy_sp.username,
                "pass": proxy_sp.password
            }
        elif isinstance(proxy, dict):
            self.proxy = proxy
        else:
            self.proxy = None

    def direct_connect(self, host, port):
        connect_timeout = 30

        if ':' in host:
            info = [(socket.AF_INET6, socket.SOCK_STREAM, 0, "", (host, port, 0, 0))]
        else:
            try:
                info = socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                          socket.SOCK_STREAM)
            except socket.gaierror:
                info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (host, port))]

        for res in info:
            af, socktype, proto, canonname, sa = res
            s = None
            try:
                s = socket.socket(af, socktype, proto)
                # See http://groups.google.com/group/cherrypy-users/
                #        browse_frm/thread/bbfe5eb39c904fe0

                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 * 1024)
                s.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                s.settimeout(connect_timeout)
                s.connect((host, port))
                return s
            except socket.error:
                if s:
                    s.close()

        return None

    def connect(self, host, port):
        return self.direct_connect(host, port)

    def request(self, method, url, headers={}, body="", read_payload=True):
        start_time = time.time()

        upl = urlparse.urlsplit(url)
        headers["Content-Length"] = str(len(body))
        headers["Host"] = upl.netloc
        port = upl.port
        if not port:
            if upl.scheme == "http":
                port = 80
            elif upl.scheme == "https":
                port = 443
            else:
                raise Exception("unknown method:%s" % upl.scheme)

        path = upl.path
        if not path:
            path = "/"

        if upl.query:
            path += "?" + upl.query

        sock = self.connect(upl.hostname, port)
        if not sock:
            return None

        if upl.scheme == "https":
            if os.path.isfile(self.cert):
                sock = ssl.wrap_socket(sock, ca_certs=self.cert)
            else:
                sock = ssl.wrap_socket(sock)

        request_data = '%s %s HTTP/1.1\r\n' % (method, path)

        request_data += ''.join('%s: %s\r\n' % (k, v) for k, v in headers.items())
        request_data += '\r\n'

        if len(request_data) + len(body) < 1300:
            body = request_data.encode() + body
        else:
            sock.send(request_data.encode())

        payload_len = len(body)
        start = 0
        while start < payload_len:
            send_size = min(payload_len - start, 65535)
            sended = sock.send(body[start:start + send_size])
            start += sended

        sock.settimeout(self.timeout)
        response = Response(sock)

        response.begin(timeout=self.timeout)

        if response.status != 200:
            #logging.warn("status:%r", response.status)
            return response

        if not read_payload:
            return response


def request(method="GET", url=None, headers={}, body="", proxy=None, timeout=60, read_payload=True):
    if not url:
        raise Exception("no url")

    client = Client(proxy, timeout=timeout)
    return client.request(method, url, headers, body, read_payload)
