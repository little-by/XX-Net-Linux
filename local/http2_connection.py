#!/usr/bin/env python
# coding:utf-8
import Queue
import threading
import socket
import errno
import struct
import time


from hyper.common.bufsocket import BufferedSocket
from hyper.common.headers import HTTPHeaderMap
from hyper.common.util import to_host_port_tuple, to_native_string, to_bytestring
from hyperframe.frame import (
    FRAMES, DataFrame, HeadersFrame, PushPromiseFrame, RstStreamFrame,
    SettingsFrame, Frame, WindowUpdateFrame, GoAwayFrame, PingFrame,
     PushPromiseFrame, ContinuationFrame, FRAME_MAX_ALLOWED_LEN, FRAME_MAX_LEN
)

from hyper.http20.window import BaseFlowControlManager
from hyper.http20.exceptions import ProtocolError, StreamResetError
from hyper.http20.util import h2_safe_headers
from hyper.http20.response import strip_headers

from hpack import Encoder, Decoder
import simple_http_client


DEFAULT_WINDOW_SIZE = 65535
DEFAULT_MAX_FRAME = FRAME_MAX_LEN

STATE_IDLE               = 0
STATE_OPEN               = 1
STATE_HALF_CLOSED_LOCAL  = 2
STATE_HALF_CLOSED_REMOTE = 3
STATE_CLOSED             = 4


class Stream(object):
    """
    A single HTTP/2 stream.

    A stream is an independent, bi-directional sequence of HTTP headers and
    data. Each stream is identified by a single integer. From a HTTP
    perspective, a stream _approximately_ matches a single request-response
    pair.
    """
    def __init__(self,
                 logger,
                 config,
                 connection,
                 ip,
                 stream_id,
                 task,
                 send_cb,
                 close_cb,
                 encoder,
                 decoder,
                 receive_window_manager,
                 remote_window_size,
                 max_frame_size):

        self.logger = logger
        self.config = config
        self.connection = connection
        self.ip = ip
        self.stream_id = stream_id
        self.task = task
        self.state = STATE_IDLE
        self.get_head_time = None

        # There are two flow control windows: one for data we're sending,
        # one for data being sent to us.
        self.receive_window_manager = receive_window_manager
        self.remote_window_size = remote_window_size
        self.max_frame_size = max_frame_size

        # This is the callback handed to the stream by its parent connection.
        # It is called when the stream wants to send data. It expects to
        # receive a list of frames that will be automatically serialized.
        self._send_cb = send_cb

        # This is the callback to be called when the stream is closed.
        self._close_cb = close_cb

        # A reference to the header encoder and decoder objects belonging to
        # the parent connection.
        self._encoder = encoder
        self._decoder = decoder

        self.request_headers = HTTPHeaderMap()

        # Convert the body to bytes if needed.
        self.request_body = to_bytestring(self.task.body)

        # request body not send blocked by send window
        # the left body will send when send window opened.
        self.request_body_left = len(self.request_body)
        self.request_body_sended = False

        # data list before decode
        self.response_header_datas = []

        # Set to a key-value set of the response headers once their
        # HEADERS..CONTINUATION frame sequence finishes.
        self.response_headers = None

        # Unconsumed response data chunks
        self.response_body = []
        self.response_body_len = 0
        self.start_time = time.time()

    def start_request(self):
        """
        Open the stream. Does this by encoding and sending the headers: no more
        calls to ``add_header`` are allowed after this method is called.
        The `end` flag controls whether this will be the end of the stream, or
        whether data will follow.
        """
        # Strip any headers invalid in H2.
        #headers = h2_safe_headers(self.request_headers)

        host = self.connection.get_host(self.task.host)

        self.add_header(":method", self.task.method)
        self.add_header(":scheme", "https")
        self.add_header(":authority", host)
        self.add_header(":path", self.task.path)

        default_headers = (':method', ':scheme', ':authority', ':path')
        #headers = h2_safe_headers(self.task.headers)
        for name, value in self.task.headers.items():
            is_default = to_native_string(name) in default_headers
            self.add_header(name, value, replace=is_default)

        # Encode the headers.
        encoded_headers = self._encoder(self.request_headers)

        # It's possible that there is a substantial amount of data here. The
        # data needs to go into one HEADERS frame, followed by a number of
        # CONTINUATION frames. For now, for ease of implementation, let's just
        # assume that's never going to happen (16kB of headers is lots!).
        # Additionally, since this is so unlikely, there's no point writing a
        # test for this: it's just so simple.
        if len(encoded_headers) > FRAME_MAX_LEN:  # pragma: no cover
            raise ValueError("Header block too large.")

        header_frame = HeadersFrame(self.stream_id)
        header_frame.data = encoded_headers

        # If no data has been provided, this is the end of the stream. Either
        # way, due to the restriction above it's definitely the end of the
        # headers.
        header_frame.flags.add('END_HEADERS')
        if self.request_body_left == 0:
            header_frame.flags.add('END_STREAM')

        # Send the header frame.
        self.task.set_state("start send header")
        self._send_cb(header_frame)

        # Transition the stream state appropriately.
        self.state = STATE_OPEN

        self.task.set_state("start send left body")
        if self.request_body_left > 0:
            self.send_left_body()

    def add_header(self, name, value, replace=False):
        """
        Adds a single HTTP header to the headers to be sent on the request.
        """
        if not replace:
            self.request_headers[name] = value
        else:
            self.request_headers.replace(name, value)

    def send_left_body(self):
        while self.remote_window_size and not self.request_body_sended:
            send_size = min(self.remote_window_size, self.request_body_left, self.max_frame_size)

            f = DataFrame(self.stream_id)
            data_start = len(self.request_body) - self.request_body_left
            f.data = self.request_body[data_start:data_start+send_size]

            self.remote_window_size -= send_size
            self.request_body_left -= send_size

            # If the length of the data is less than MAX_CHUNK, we're probably
            # at the end of the file. If this is the end of the data, mark it
            # as END_STREAM.
            if self.request_body_left == 0:
                f.flags.add('END_STREAM')

            # Send the frame and decrement the flow control window.
            self._send_cb(f)

            # If no more data is to be sent on this stream, transition our state.
            if self.request_body_left == 0:
                self.request_body_sended = True
                self._close_local()
                self.task.set_state("end send left body")

    def receive_frame(self, frame):
        """
        Handle a frame received on this stream.
        called by connection.
        """
        # self.logger.debug("stream %d recved frame %r", self.stream_id, frame)
        if frame.type == WindowUpdateFrame.type:
            self.remote_window_size += frame.window_increment
            self.send_left_body()
        elif frame.type == HeadersFrame.type:
            # Begin the header block for the response headers.
            #self.response_header_datas = [frame.data]
            self.response_header_datas.append(frame.data)
        elif frame.type == PushPromiseFrame.type:
            self.logger.error("%s receive PushPromiseFrame:%d", self.ip, frame.stream_id)
        elif frame.type == ContinuationFrame.type:
            # Continue a header block begun with either HEADERS or PUSH_PROMISE.
            self.response_header_datas.append(frame.data)
        elif frame.type == DataFrame.type:
            # Append the data to the buffer.
            if not self.task.finished:
                self.task.put_data(frame.data)

            if 'END_STREAM' not in frame.flags:
                # Increase the window size. Only do this if the data frame contains
                # actual data.
                # don't do it if stream is closed.
                size = frame.flow_controlled_length
                increment = self.receive_window_manager._handle_frame(size)
                #if increment:
                #    self.logger.debug("stream:%d frame size:%d increase win:%d", self.stream_id, size, increment)

                #content_len = int(self.request_headers.get("Content-Length")[0])
                #self.logger.debug("%s get:%d s:%d", self.ip, self.response_body_len, size)

                if increment and not self._remote_closed:
                    w = WindowUpdateFrame(self.stream_id)
                    w.window_increment = increment
                    self._send_cb(w)

        elif frame.type == RstStreamFrame.type:
            # Rest Frame send from server is not define in RFC
            inactive_time = time.time() - self.connection.last_recv_time
            self.logger.debug("%s Stream %d Rest by server, inactive:%d. error code:%d",
                       self.ip, self.stream_id, inactive_time, frame.error_code)
            self.connection.close("RESET")
        elif frame.type in FRAMES:
            # This frame isn't valid at this point.
            #raise ValueError("Unexpected frame %s." % frame)
            self.logger.error("%s Unexpected frame %s.", self.ip, frame)
        else:  # pragma: no cover
            # Unknown frames belong to extensions. Just drop it on the
            # floor, but log so that users know that something happened.
            self.logger.error("%s Received unknown frame, type %d", self.ip, frame.type)
            pass

        if 'END_HEADERS' in frame.flags:
            if self.response_headers is not None:
                raise ProtocolError("Too many header blocks.")

            # Begin by decoding the header block. If this fails, we need to
            # tear down the entire connection.
            if len(self.response_header_datas) == 1:
                header_data = self.response_header_datas[0]
            else:
                header_data = b''.join(self.response_header_datas)

            try:
                headers = self._decoder.decode(header_data)
            except Exception as e:
                #self.logger.exception("decode h2 header %s fail:%r", header_data, e)
                raise

            self.response_headers = HTTPHeaderMap(headers)

            # We've handled the headers, zero them out.
            self.response_header_datas = None

            self.get_head_time = time.time()

            length = self.response_headers.get("Content-Length", None)
            if isinstance(length, list):
                length = int(length[0])
            if not self.task.finished:
                self.task.content_length = length
                self.task.set_state("h2_get_head")
                self.send_response()

        if 'END_STREAM' in frame.flags:
            #self.logger.debug("%s Closing remote side of stream:%d", self.ip, self.stream_id)
            time_now = time.time()
            time_cost = time_now - self.get_head_time
            if time_cost > 0 and \
                    isinstance(self.task.content_length, int) and \
                    not self.task.finished:
                speed = self.task.content_length / time_cost
                self.task.set_state("h2_finish[SP:%d]" % speed)

            self._close_remote()

            self.close("end stream")
            if not self.task.finished:
                self.connection.continue_timeout = 0

    def send_response(self):
        if self.task.responsed:
            #self.logger.error("http2_stream send_response but responsed.%s", self.task.url)
            self.close("")
            return

        self.task.responsed = True
        status = int(self.response_headers[b':status'][0])
        strip_headers(self.response_headers)
        response = simple_http_client.BaseResponse(status=status, headers=self.response_headers)
        response.ssl_sock = self.connection.ssl_sock
        response.worker = self.connection
        response.task = self.task
        self.task.queue.put(response)
        if status in self.config.http2_status_to_close:
            self.connection.close("status %d" % status)

    def close(self, reason="close"):
        if not self.task.responsed:
            self.connection.retry_task_cb(self.task, reason)
        else:
            self.task.finish()
            # empty block means fail or closed.
        self._close_remote()
        self._close_cb(self.stream_id, reason)

    @property
    def _local_closed(self):
        return self.state in (STATE_CLOSED, STATE_HALF_CLOSED_LOCAL)

    @property
    def _remote_closed(self):
        return self.state in (STATE_CLOSED, STATE_HALF_CLOSED_REMOTE)

    @property
    def _local_open(self):
        return self.state in (STATE_OPEN, STATE_HALF_CLOSED_REMOTE)

    def _close_local(self):
        self.state = (
            STATE_HALF_CLOSED_LOCAL if self.state == STATE_OPEN
            else STATE_CLOSED
        )

    def _close_remote(self):
        self.state = (
            STATE_HALF_CLOSED_REMOTE if self.state == STATE_OPEN
            else STATE_CLOSED
        )

    def check_timeout(self, now):
        if time.time() - self.start_time < self.task.timeout:
            return

        if self._remote_closed:
            return

        self.logger.warn("h2 timeout %s task_trace:%s worker_trace:%s",
                  self.connection.ssl_sock.ip,
                  self.task.get_trace(),
                  self.connection.get_trace())
        self.task.set_state("timeout")

        if self.task.responsed:
            self.task.finish()
        else:
            self.task.response_fail("timeout")

        self.connection.continue_timeout += 1
        

class WriteBuffer(object):
    def __init__(self, s=None):
        if isinstance(s, str):
            self.string_len = len(s)
            self.buffer_list = [s]
        else:
            self.reset()

    def reset(self):
        self.buffer_list = []
        self.string_len = 0

    def __len__(self):
        return self.string_len

    def __add__(self, other):
        self.append(other)
        return self

    def insert(self, s):
        if isinstance(s, WriteBuffer):
            self.buffer_list = s.buffer_list + self.buffer_list
            self.string_len += s.string_len
        elif isinstance(s, str):
            self.buffer_list.insert(0, s)
            self.string_len += len(s)
        else:
            raise Exception("WriteBuffer append not string or StringBuffer")

    def append(self, s):
        if isinstance(s, WriteBuffer):
            self.buffer_list.extend(s.buffer_list)
            self.string_len += s.string_len
        elif isinstance(s, str):
            self.buffer_list.append(s)
            self.string_len += len(s)
        else:
            raise Exception("WriteBuffer append not string or StringBuffer")

    def __str__(self):
        return self.get_string()

    def get_string(self):
        return "".join(self.buffer_list)

BufferedSocket.send_buffer = WriteBuffer()

def send(self, buf, flush=True):
    self.send_buffer.append(buf)

    if len(self.send_buffer) > 1300 or flush:
        self.flush()

def flush(self):
    if len(self.send_buffer):
        data = self.send_buffer.get_string()
        # logger.debug("buffer socket flush:%d", len(data))
        self.send_buffer.reset()

        data_len = len(data)
        start = 0
        while start < data_len:
            send_size = min(data_len - start, 65535)
            sended = self._sck.send(data[start:start+send_size])
            start += sended

BufferedSocket.send = send
BufferedSocket.flush = flush

class FlowControlManager(BaseFlowControlManager):
    """
    ``hyper``'s default flow control manager.

    This implements hyper's flow control algorithms. This algorithm attempts to
    reduce the number of WINDOWUPDATE frames we send without blocking the remote
    endpoint behind the flow control window.

    This algorithm will become more complicated over time. In the current form,
    the algorithm is very simple:
        - When the flow control window gets less than 3/4 of the maximum size,
          increment back to the maximum.
        - Otherwise, if the flow control window gets to less than 1kB, increment
          back to the maximum.
    """
    def increase_window_size(self, frame_size):
        future_window_size = self.window_size - frame_size

        if ((future_window_size < (self.initial_window_size * 3 / 4)) or
            (future_window_size < 1000)):
            return self.initial_window_size - future_window_size

        return 0

    def blocked(self):
        return self.initial_window_size - self.window_size


class RawFrame(object):
    def __init__(self, dat):
        self.dat = dat

    def serialize(self):
        return self.dat

    def __repr__(self):
        out_str = "{type}".format(type=type(self).__name__)
        return out_str


class HttpWorker(object):
    def __init__(self, logger, ip_manager, config, ssl_sock, close_cb, retry_task_cb, idle_cb):
        self.logger = logger
        self.ip_manager = ip_manager
        self.config = config
        self.ssl_sock = ssl_sock
        self.init_rtt = ssl_sock.handshake_time / 3
        self.rtt = self.init_rtt
        self.speed = 1
        self.ip = ssl_sock.ip
        self.close_cb = close_cb
        self.retry_task_cb = retry_task_cb
        self.idle_cb = idle_cb
        self.accept_task = True
        self.keep_running = True
        self.processed_tasks = 0
        self.speed_history = []
        self.last_recv_time = self.ssl_sock.create_time
        self.last_send_time = self.ssl_sock.create_time

    def close(self, reason):
        self.accept_task = False
        self.keep_running = False
        self.ssl_sock.close()
        if reason not in ["idle timeout"]:
            self.logger.debug("%s worker close:%s", self.ip, reason)
        self.ip_manager.report_connect_closed(self.ssl_sock.ip, reason)
        self.close_cb(self)

    def get_score(self):
        now = time.time()
        inactive_time = now - self.last_recv_time

        rtt = self.rtt
        if inactive_time > 30:
            if rtt > 1000:
                rtt = 1000

        if self.version == "1.1":
            rtt += 100
        else:
            rtt += len(self.streams) * 500

        if inactive_time > 1:
            score = rtt
        elif inactive_time < 0.1:
            score = rtt + 1000
        else:
            # inactive_time < 2
            score = rtt + (1 / inactive_time) * 1000

        return score

    def get_host(self, task_host):
        if task_host:
            return task_host
        else:
            return self.ssl_sock.host
            

class Http2Worker(HttpWorker):
    version = "2"

    def __init__(self, logger, ip_manager, config, ssl_sock, close_cb, retry_task_cb, idle_cb):
        super(Http2Worker, self).__init__(
            logger, ip_manager, config, ssl_sock, close_cb, retry_task_cb, idle_cb)

        self.network_buffer_size = 65535

        # Google http/2 time out is 4 mins.
        self.ssl_sock.settimeout(240)
        self._sock = BufferedSocket(ssl_sock, self.network_buffer_size)

        self.next_stream_id = 1
        self.streams = {}
        self.last_ping_time = time.time()
        self.continue_timeout = 0

        # count ping not ACK
        # increase when send ping
        # decrease when recv ping ack
        # if this in not 0, don't accept request.
        self.ping_on_way = 0
        self.accept_task = False

        # request_lock
        self.request_lock = threading.Lock()

        # all send frame must put to this queue
        # then send by send_loop
        # every frame put to this queue must allowed by stream window and connection window
        # any data frame blocked by connection window should put to self.blocked_send_frames
        self.send_queue = Queue.Queue()
        self.encoder = Encoder()
        self.decoder = Decoder()

        # keep blocked data frame in this buffer
        # which is allowed by stream window but blocked by connection window.
        # They will be sent when connection window open
        self.blocked_send_frames = []

        # Values for the settings used on an HTTP/2 connection.
        # will send to remote using Setting Frame
        self.local_settings = {
            SettingsFrame.INITIAL_WINDOW_SIZE: 16 * 1024 * 1024,
            SettingsFrame.MAX_FRAME_SIZE: 256 * 1024
        }
        self.local_connection_initial_windows = 32 * 1024 * 1024
        self.local_window_manager = FlowControlManager(self.local_connection_initial_windows)

        # changed by server, with SettingFrame
        self.remote_settings = {
            SettingsFrame.INITIAL_WINDOW_SIZE: DEFAULT_WINDOW_SIZE,
            SettingsFrame.MAX_FRAME_SIZE: DEFAULT_MAX_FRAME,
            SettingsFrame.MAX_CONCURRENT_STREAMS: 100
        }

        #self.remote_window_size = DEFAULT_WINDOW_SIZE
        self.remote_window_size = 32 * 1024 * 1024

        # send Setting frame before accept task.
        self._send_preamble()

        threading.Thread(target=self.send_loop).start()
        threading.Thread(target=self.recv_loop).start()

    # export api
    def request(self, task):
        if not self.keep_running:
            # race condition
            self.retry_task_cb(task)
            return

        if len(self.streams) > self.config.http2_max_concurrent:
            self.accept_task = False

        task.set_state("h2_req")
        self.request_task(task)

    def encode_header(self, headers):
        return self.encoder.encode(headers)

    def request_task(self, task):
        with self.request_lock:
            # create stream to process task
            stream_id = self.next_stream_id

            # http/2 client use odd stream_id
            self.next_stream_id += 2

            stream = Stream(self.logger, self.config, self, self.ip, stream_id, task,
                        self._send_cb, self._close_stream_cb, self.encode_header, self.decoder,
                        FlowControlManager(self.local_settings[SettingsFrame.INITIAL_WINDOW_SIZE]),
                        self.remote_settings[SettingsFrame.INITIAL_WINDOW_SIZE],
                        self.remote_settings[SettingsFrame.MAX_FRAME_SIZE])
            self.streams[stream_id] = stream
            stream.start_request()

    def send_loop(self):
        while self.keep_running:
            frame = self.send_queue.get(True)
            if not frame:
                # None frame means exist
                break

            if self.config.http2_show_debug:
                self.logger.debug("%s Send:%s", self.ip, str(frame))
            data = frame.serialize()

            self._sock.send(data, flush=False)
            # don't flush for small package
            # reduce send api call

            if self.send_queue._qsize():
                continue

            # wait for payload frame
            time.sleep(0.01)
            # combine header and payload in one tcp package.
            if not self.send_queue._qsize():
                self._sock.flush()

            self.last_send_time = time.time()

    def recv_loop(self):
        while self.keep_running:
            self._consume_single_frame()


    def get_rtt_rate(self):
        return self.rtt + len(self.streams) * 3000

    def close(self, reason="conn close"):
        self.keep_running = False
        self.accept_task = False
        # Notify loop to exit
        # This function may be call by out side http2
        # When gae_proxy found the appid or ip is wrong
        self.send_queue.put(None)

        for stream in self.streams.values():
            if stream.task.responsed:
                # response have send to client
                # can't retry
                stream.close(reason=reason)
            else:
                self.retry_task_cb(stream.task)
        self.streams = {}
        super(Http2Worker, self).close(reason)

    def send_ping(self):
        p = PingFrame(0)
        p.opaque_data = struct.pack("!d", time.time())
        self.send_queue.put(p)
        self.last_ping_time = time.time()
        self.ping_on_way += 1

    def _send_preamble(self):
        self.send_queue.put(RawFrame(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'))

        f = SettingsFrame(0)
        f.settings[SettingsFrame.ENABLE_PUSH] = 0
        f.settings[SettingsFrame.INITIAL_WINDOW_SIZE] = self.local_settings[SettingsFrame.INITIAL_WINDOW_SIZE]
        f.settings[SettingsFrame.MAX_FRAME_SIZE] = self.local_settings[SettingsFrame.MAX_FRAME_SIZE]
        self._send_cb(f)

        # update local connection windows size
        f = WindowUpdateFrame(0)
        f.window_increment = self.local_connection_initial_windows - DEFAULT_WINDOW_SIZE
        self._send_cb(f)

    def increase_remote_window_size(self, inc_size):
        # check and send blocked frames if window allow
        self.remote_window_size += inc_size
        #self.logger.debug("%s increase send win:%d result:%d", self.ip, inc_size, self.remote_window_size)
        while len(self.blocked_send_frames):
            frame = self.blocked_send_frames[0]
            if len(frame.data) > self.remote_window_size:
                return

            self.remote_window_size -= len(frame.data)
            self.send_queue.put(frame)
            self.blocked_send_frames.pop(0)

        if self.keep_running and \
                self.accept_task == False and \
                len(self.streams) < self.config.http2_max_concurrent and \
                self.remote_window_size > 10000:
            self.accept_task = True
            self.idle_cb()

    def _send_cb(self, frame):
        # can called by stream
        # put to send_blocked if connection window not allow,
        if frame.type == DataFrame.type:
            if len(frame.data) > self.remote_window_size:
                self.blocked_send_frames.append(frame)
                self.accept_task = False
                return
            else:
                self.remote_window_size -= len(frame.data)
                self.send_queue.put(frame)
        else:
            self.send_queue.put(frame)

    def _close_stream_cb(self, stream_id, reason):
        # call by stream to remove from streams list
        # self.logger.debug("%s close stream:%d %s", self.ssl_sock.ip, stream_id, reason)
        try:
            del self.streams[stream_id]
        except KeyError:
            pass

        if self.keep_running and \
                len(self.streams) < self.config.http2_max_concurrent and \
                self.remote_window_size > 10000:
            self.accept_task = True
            self.idle_cb()

        self.processed_tasks += 1

    def _consume_single_frame(self):
        try:
            header = self._sock.recv(9)
        except Exception as e:
            self.logger.debug("%s _consume_single_frame:%r, inactive time:%d", self.ip, e, time.time() - self.last_recv_time)
            self.close("ConnectionReset:%r" % e)
            return
        self.last_recv_time = time.time()

        # Parse the header. We can use the returned memoryview directly here.
        frame, length = Frame.parse_frame_header(header)

        if length > FRAME_MAX_ALLOWED_LEN:
            self.logger.error("%s Frame size exceeded on stream %d (received: %d, max: %d)",
                self.ip, frame.stream_id, length, FRAME_MAX_LEN)
            # self._send_rst_frame(frame.stream_id, 6) # 6 = FRAME_SIZE_ERROR

        try:
            data = self._recv_payload(length)
        except Exception as e:
            self.close("ConnectionReset:%r" % e)
            return

        self._consume_frame_payload(frame, data)

    def _recv_payload(self, length):
        if not length:
            return memoryview(b'')

        buffer = bytearray(length)
        buffer_view = memoryview(buffer)
        index = 0
        data_length = -1

        # _sock.recv(length) might not read out all data if the given length
        # is very large. So it should be to retrieve from socket repeatedly.
        while length and data_length:
            data = self._sock.recv(length)
            self.last_recv_time = time.time()
            data_length = len(data)
            end = index + data_length
            buffer_view[index:end] = data[:]
            length -= data_length
            index = end

        return buffer_view[:end]

    def _consume_frame_payload(self, frame, data):
        frame.parse_body(data)

        if self.config.http2_show_debug:
            self.logger.debug("%s Recv:%s", self.ip, str(frame))

        # Maintain our flow control window. We do this by delegating to the
        # chosen WindowManager.
        if frame.type == DataFrame.type:

            size = frame.flow_controlled_length
            increment = self.local_window_manager._handle_frame(size)

            if increment < 0:
                self.logger.warn("increment:%d", increment)
            elif increment:
                #self.logger.debug("%s frame size:%d increase win:%d", self.ip, size, increment)
                w = WindowUpdateFrame(0)
                w.window_increment = increment
                self._send_cb(w)

        elif frame.type == PushPromiseFrame.type:
            self.logger.error("%s receive push frame", self.ip,)

        # Work out to whom this frame should go.
        if frame.stream_id != 0:
            if frame.stream_id in self.streams:
                stream = self.streams[frame.stream_id]
                stream.receive_frame(frame)
        else:
            self.receive_frame(frame)

    def receive_frame(self, frame):
        if frame.type == WindowUpdateFrame.type:
            # self.logger.debug("WindowUpdateFrame %d", frame.window_increment)
            self.increase_remote_window_size(frame.window_increment)

        elif frame.type == PingFrame.type:
            if 'ACK' in frame.flags:
                ping_time = struct.unpack("!d", frame.opaque_data)[0]
                time_now = time.time()
                rtt = (time_now - ping_time) * 1000
                if rtt < 0:
                    self.logger.error("rtt:%f ping_time:%f now:%f", rtt, ping_time, time_now)
                self.rtt = rtt
                self.ping_on_way -= 1
                #self.logger.debug("RTT:%d, on_way:%d", self.rtt, self.ping_on_way)
                if self.keep_running and self.ping_on_way == 0:
                    self.accept_task = True
            else:
                # The spec requires us to reply with PING+ACK and identical data.
                p = PingFrame(0)
                p.flags.add('ACK')
                p.opaque_data = frame.opaque_data
                self._send_cb(p)

        elif frame.type == SettingsFrame.type:
            if 'ACK' not in frame.flags:
                # send ACK as soon as possible
                f = SettingsFrame(0)
                f.flags.add('ACK')
                self._send_cb(f)

                # this may trigger send DataFrame blocked by remote window
                self._update_settings(frame)
            else:
                self.accept_task = True
                self.idle_cb()

        elif frame.type == GoAwayFrame.type:
            # If we get GoAway with error code zero, we are doing a graceful
            # shutdown and all is well. Otherwise, throw an exception.

            # If an error occured, try to read the error description from
            # code registry otherwise use the frame's additional data.
            #error_string = frame._extra_info()
            time_cost = time.time() - self.last_recv_time
            if frame.additional_data != "session_timed_out":
                pass
                #self.logger.warn("goaway:%s, t:%d", error_string, time_cost)

            self.close("conn close")

        #elif frame.type == BlockedFrame.type:self.logger.warn("%s get BlockedFrame", self.ip)
            
        elif frame.type in FRAMES:
            # This frame isn't valid at this point.
            #raise ValueError("Unexpected frame %s." % frame)
            self.logger.error("%s Unexpected frame %s.", self.ip, frame)
        else:  # pragma: no cover
            # Unexpected frames belong to extensions. Just drop it on the
            # floor, but log so that users know that something happened.
            self.logger.error("%s Received unknown frame, type %d", self.ip, frame.type)

    def _update_settings(self, frame):
        if SettingsFrame.HEADER_TABLE_SIZE in frame.settings:
            new_size = frame.settings[SettingsFrame.HEADER_TABLE_SIZE]

            self.remote_settings[SettingsFrame.HEADER_TABLE_SIZE] = new_size
            #self.encoder.header_table_size = new_size

        if SettingsFrame.INITIAL_WINDOW_SIZE in frame.settings:
            newsize = frame.settings[SettingsFrame.INITIAL_WINDOW_SIZE]
            oldsize = self.remote_settings[SettingsFrame.INITIAL_WINDOW_SIZE]
            delta = newsize - oldsize

            for stream in self.streams.values():
                stream.remote_window_size += delta

            self.remote_settings[SettingsFrame.INITIAL_WINDOW_SIZE] = newsize

        if SettingsFrame.MAX_FRAME_SIZE in frame.settings:
            new_size = frame.settings[SettingsFrame.MAX_FRAME_SIZE]
            if not (FRAME_MAX_LEN <= new_size <= FRAME_MAX_ALLOWED_LEN):
                self.logger.error("%s Frame size %d is outside of allowed range", self.ip, new_size)

                # Tear the connection down with error code PROTOCOL_ERROR
                self.close("bad max frame size")
                #error_string = ("Advertised frame size %d is outside of range" % (new_size))
                #raise ConnectionError(error_string)
                return

            self.remote_settings[SettingsFrame.MAX_FRAME_SIZE] = new_size

            for stream in self.streams.values():
                stream.max_frame_size += new_size

    def get_trace(self):
        out_list = []
        out_list.append(" continue_timeout:%d" % self.continue_timeout)
        out_list.append(" processed:%d" % self.processed_tasks)
        out_list.append(" h2.stream_num:%d" % len(self.streams))
        out_list.append(" sni:%s, host:%s" % (self.ssl_sock.sni, self.ssl_sock.host))
        return ",".join(out_list)

    def check_active(self, now):
        if not self.keep_running or len(self.streams) == 0:
            return

        for sid in self.streams.keys():
            try:
                stream = self.streams[sid]
                stream.check_timeout(now)
            except:
                pass

        if len(self.streams) > 0 and\
                now - self.last_send_time > 3 and \
                now - self.last_ping_time > self.config.http2_ping_min_interval:

            if self.ping_on_way > 0:
                self.close("active timeout")
                return

            self.send_ping()
