#!/usr/bin/env python2
# coding:utf-8
import Queue
import operator
import threading
import time
import traceback

import simple_queue
from http2_connection import Http2Worker
import simple_http_client

class Task(object):
    def __init__(self, logger, config, method, host, path, headers, body, queue, url, timeout):
        self.logger = logger
        self.config = config
        self.method = method
        self.host = host
        self.path = path
        self.headers = headers
        self.body = body
        self.queue = queue
        self.url = url
        self.timeout = timeout
        self.start_time = time.time()
        self.unique_id = "%s:%f" % (url, self.start_time)
        self.trace_time = []
        self.body_queue = simple_queue.Queue()
        self.body_len = 0
        self.body_readed = 0
        self.content_length = None
        self.worker = None
        self.read_buffers = []
        self.read_buffer_len = 0

        self.responsed = False
        self.finished = False
        self.retry_count = 0

    def to_string(self):
        out_str = " Task:%s\r\n" % self.url
        out_str += "   responsed:%d" % self.responsed
        out_str += "   retry_count:%d" % self.retry_count
        out_str += "   start_time:%d" % (time.time() - self.start_time)
        out_str += "   body_readed:%d\r\n" % self.body_readed
        out_str += "   Trace:%s" % self.get_trace()
        out_str += "\r\n"
        return out_str

    def put_data(self, data):
        # hyper H2
        if isinstance(data, memoryview):
            data = data.tobytes()
        self.body_queue.put(data)
        self.body_len += len(data)

    def read(self, size=None):
        # fail or cloe if return ""
        if self.body_readed == self.content_length:
            return b''

        if size:
            while self.read_buffer_len < size:
                data = self.body_queue.get(self.timeout)
                if not data:
                    return b''

                self.read_buffers.append(data)
                self.read_buffer_len += len(data)

            if len(self.read_buffers[0]) == size:
                data = self.read_buffers[0]
                self.read_buffers.pop(0)
                self.read_buffer_len -= size
            elif len(self.read_buffers[0]) > size:
                data = self.read_buffers[0][:size]
                self.read_buffers[0] = self.read_buffers[0][size:]
                self.read_buffer_len -= size
            else:
                buff = bytearray(self.read_buffer_len)
                buff_view = memoryview(buff)
                p = 0
                for data in self.read_buffers:
                    buff_view[p:p+len(data)] = data
                    p += len(data)

                if self.read_buffer_len == size:
                    self.read_buffers = []
                    self.read_buffer_len = 0
                    data = buff_view.tobytes()
                else:
                    data = buff_view[:size].tobytes()

                    self.read_buffers = [buff_view[size:].tobytes()]
                    self.read_buffer_len -= size

        else:
            if self.read_buffers:
                data = self.read_buffers.pop(0)
                self.read_buffer_len -= len(data)
            else:
                data = self.body_queue.get(self.timeout)
                if not data:
                    return b''

        self.body_readed += len(data)
        return data

    def set_state(self, stat):
        # for debug trace
        time_now = time.time()
        self.trace_time.append((time_now, stat))
        if self.config.show_state_debug:
            self.logger.debug("%s stat:%s", self.unique_id, stat)
        return time_now

    def get_trace(self):
        out_list = []
        last_time = self.start_time
        for t, stat in self.trace_time:
            time_diff = int((t - last_time) * 1000)
            last_time = t
            out_list.append("%d:%s" % (time_diff, stat))
        out_list.append(":%d" % ((time.time()-last_time)*1000))
        return ",".join(out_list)

    def response_fail(self, reason=""):
        if self.responsed:
            self.logger.error("http_common responsed_fail but responed.%s", self.url)
            self.put_data("")
            return

        self.responsed = True
        err_text = "response_fail:%s" % reason
        self.logger.warn("%s %s", self.url, err_text)
        res = simple_http_client.BaseResponse(body=err_text)
        res.task = self
        res.worker = self.worker
        self.queue.put(res)
        self.finish()

    def finish(self):
        if self.finished:
            return

        self.put_data("")
        self.finished = True


class SimpleCondition(object):
    def __init__(self):
        self.lock = threading.Condition()

    def notify(self):
        self.lock.acquire()
        self.lock.notify()
        self.lock.release()

    def wait(self):
        self.lock.acquire()
        self.lock.wait()
        self.lock.release()


class HttpsDispatcher(object):
    idle_time = 2 * 60

    def __init__(self, logger, config, ip_manager, connection_manager, http2worker=Http2Worker):
                 
        self.logger = logger
        self.config = config
        self.ip_manager = ip_manager
        self.connection_manager = connection_manager
        self.connection_manager.set_ssl_created_cb(self.on_ssl_created_cb)

        self.http2worker = http2worker

        self.request_queue = Queue.Queue()
        self.workers = []
        self.working_tasks = {}
        self.h1_num = 0
        self.h2_num = 0
        self.last_request_time = time.time()
        self.task_count_lock = threading.Lock()
        self.task_count = 0
        self.running = True

        # for statistic
        self.success_num = 0
        self.fail_num = 0
        self.continue_fail_num = 0
        self.last_fail_time = 0
        self.rtts = []
        self.last_sent = self.total_sent = 0
        self.last_received = self.total_received = 0
        self.second_stats = Queue.deque()
        self.last_statistic_time = time.time()
        self.second_stat = {
            "rtt": 0,
            "sent": 0,
            "received": 0
        }
        self.minute_stat = {
            "rtt": 0,
            "sent": 0,
            "received": 0
        }

        self.trigger_create_worker_cv = SimpleCondition()
        self.wait_a_worker_cv = simple_queue.Queue()

        threading.Thread(target=self.dispatcher).start()
        threading.Thread(target=self.create_worker_thread).start()
        threading.Thread(target=self.connection_checker).start()

    def stop(self):
        self.running = False
        self.request_queue.put(None)
        self.close_all_worker("stop")

    def on_ssl_created_cb(self, ssl_sock, check_free_work=False):
        # self.logger.debug("on_ssl_created_cb %s", ssl_sock.ip)
        if not self.running:
            ssl_sock.close()
            return

        if not ssl_sock:
            raise Exception("on_ssl_created_cb ssl_sock None")

        worker = self.http2worker(
            self.logger, self.ip_manager, self.config, ssl_sock,
          self.close_cb, self.retry_task_cb, self._on_worker_idle_cb)
        self.h2_num += 1

        self.workers.append(worker)

    def _on_worker_idle_cb(self):
        self.wait_a_worker_cv.notify()

    def create_worker_thread(self):
        while self.running:
            self.trigger_create_worker_cv.wait()

            try:
                ssl_sock = self.connection_manager.get_ssl_connection()
            except Exception as e:
                continue

            if not ssl_sock:
                # self.logger.warn("create_worker_thread get ssl_sock fail")
                continue

            try:
                self.on_ssl_created_cb(ssl_sock, check_free_work=False)
            except:
                time.sleep(10)

            idle_num = 0
            acceptable_num = 0
            for worker in self.workers:
                if worker.accept_task:
                    acceptable_num += 1

                if worker.version == "1.1":
                    if worker.accept_task:
                        idle_num += 1
                else:
                    if len(worker.streams) == 0:
                        idle_num += 1

    def get_worker(self, nowait=False):
        while self.running:
            best_score = 99999999
            best_worker = None
            idle_num = 0
            now = time.time()
            for worker in self.workers:
                if not worker.accept_task:
                    # self.logger.debug("not accept")
                    continue

                if worker.version == "1.1":
                    idle_num += 1
                else:
                    if len(worker.streams) == 0:
                        idle_num += 1

                score = worker.get_score()

                if best_score > score:
                    best_score = score
                    best_worker = worker

            if len(self.workers) < self.config.dispather_max_workers and \
                    (best_worker is None or
                    idle_num < self.config.dispather_min_idle_workers or
                    len(self.workers) < self.config.dispather_min_workers or
                    (now - best_worker.last_recv_time) < self.config.dispather_work_min_idle_time or
                    best_score > self.config.dispather_work_max_score or
                     (best_worker.version == "2" and len(best_worker.streams) >= self.config.http2_target_concurrent)):
                # self.logger.debug("trigger get more worker")
                self.trigger_create_worker_cv.notify()

            if nowait or \
                    (best_worker and (now - best_worker.last_recv_time) >= self.config.dispather_work_min_idle_time):
                # self.logger.debug("return worker")
                return best_worker

            self.wait_a_worker_cv.wait(time.time() + 1)


    def request(self, method, host, path, headers, body, url="", timeout=60):
        if self.task_count > self.config.max_task_num:
            self.logger.warn("task num exceed")
            time.sleep(1)
            return None

        with self.task_count_lock:
            self.task_count += 1

        try:
            # self.logger.debug("task start request")
            if not url:
                url = "%s %s%s" % (method, host, path)
            self.last_request_time = time.time()
            q = simple_queue.Queue()
            task = Task(self.logger, self.config, method, host, path, headers, body, q, url, timeout)
            task.set_state("start_request")
            self.request_queue.put(task)

            response = q.get(timeout=timeout)
            if response and response.status == 200:
                self.success_num += 1
                self.continue_fail_num = 0
            else:
                self.logger.warn("task %s %s %s timeout", method, host, path)
                self.fail_num += 1
                self.continue_fail_num += 1
                self.last_fail_time = time.time()

            task.set_state("get_response")
            return response
        finally:
            with self.task_count_lock:
                self.task_count -= 1

    def retry_task_cb(self, task, reason=""):
        self.fail_num += 1
        self.continue_fail_num += 1
        self.last_fail_time = time.time()
        self.logger.warn("retry_task_cb: %s", task.url)

        if task.responsed:
            self.logger.warn("retry but responsed. %s", task.url)
            st = traceback.extract_stack()
            stl = traceback.format_list(st)
            self.logger.warn("stack:%r", repr(stl))
            task.finish()
            return

        if task.retry_count > 10:
            task.response_fail("retry time exceed 10")
            return

        if time.time() - task.start_time > task.timeout:
            task.response_fail("retry timeout:%d" % (time.time() - task.start_time))
            return

        if not self.running:
            task.response_fail("retry but stopped.")
            return

        task.set_state("retry(%s)" % reason)
        task.retry_count += 1
        self.request_queue.put(task)

    def dispatcher(self):
        while self.running:
            start_time = time.time()
            try:
                task = self.request_queue.get(True)
                if task is None:
                    # exit
                    break
            except Exception as e:
                self.logger.exception("http_dispatcher dispatcher request_queue.get fail:%r", e)
                continue
            get_time = time.time()
            get_cost = get_time - start_time

            task.set_state("get_task(%d)" % get_cost)
            try:
                worker = self.get_worker()
            except Exception as e:
                self.logger.warn("get worker fail:%r", e)
                task.response_fail(reason="get worker fail:%r" % e)
                continue

            if worker is None:
                # can send because exit.
                self.logger.warn("http_dispatcher get None worker")
                task.response_fail("get worker fail.")
                continue

            get_worker_time = time.time()
            get_cost = get_worker_time - get_time
            task.set_state("get_worker(%d):%s" % (get_cost, worker.ip))
            task.worker = worker
            try:
                worker.request(task)
            except Exception as e:
                self.logger.exception("dispatch request:%r", e)

        # wait up threads to exit.
        self.wait_a_worker_cv.notify()
        self.trigger_create_worker_cv.notify()

    def connection_checker(self):
        while self.running:
            now = time.time()
            try:
                for worker in list(self.workers):
                    if worker.version == "1.1":
                        continue

                    worker.check_active(now)
            except Exception as e:
                self.logger.exception("check worker except:%r")

            time.sleep(1)

    def is_idle(self):
        return time.time() - self.last_request_time > self.idle_time

    def close_cb(self, worker):
        try:
            self.workers.remove(worker)
            if worker.version == "2":
                self.h2_num -= 1
            else:
                self.h1_num -= 1
        except:
            pass

    def close_all_worker(self, reason="close all worker"):
        for w in list(self.workers):
            if w.accept_task:
                w.close(reason)

        self.workers = []
        self.h1_num = 0
        self.h2_num = 0
