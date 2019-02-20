#!/usr/bin/env python2
# coding:utf-8
import os
import random
import threading
import time
import os

from logger import logger
import check_local_network
from config import config
#import host_manager
from openssl_wrap import SSLContext
from connect_creator import ConnectCreator
from ip_manager import IpManager
from http_dispatcher import HttpsDispatcher
from connect_manager import ConnectManager
#from appid_manager import AppidManager

current_path = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.abspath(os.path.join(current_path, os.pardir, 'data'))


class HostManager(object):
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.appid_manager = None
      

    def get_host(self):
        if not self.appid_manager:
            return ""

        appid = self.appid_manager.get()
        return appid + ".appspot.com"

    def get_sni_host(self, ip):
                
        host = self.get_host()
        return "", host


class AppidManager(object):
    lock = threading.Lock()

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.check_api = None
        self.ip_manager = None
        self.reset_appid()

    def reset_appid(self):
        # called by web_control
        with self.lock:
            self.working_appid_list = list()
            for appid in self.config.GAE_APPIDS:
                self.working_appid_list.append(appid)
            self.not_exist_appids = []
            self.out_of_quota_appids = []
        self.last_reset_time = time.time()

    def get(self):
        appid = random.choice(self.working_appid_list)
        return str(appid)


class Front(object):
    name = "gae_front"

    def __init__(self):
        self.logger = logger
        self.config = config

    def start(self):
        self.running = True

        ca_certs = os.path.join(current_path, "cacert.pem")
        self.openssl_context = SSLContext(
            logger,
            ca_certs=ca_certs,
            support_http2=config.support_http2,
            cipher_suites=[
                'ALL',
                "!RC4-SHA",
                "!ECDHE-RSA-RC4-SHA",
                "!ECDHE-RSA-AES128-GCM-SHA256",
                "!AES128-GCM-SHA256",
                "!ECDHE-RSA-AES128-SHA",
                "!AES128-SHA"])

        self.appid_manager = AppidManager(self.config, logger)

        self.host_manager = HostManager(self.config, logger)
        self.host_manager.appid_manager = self.appid_manager

        self.connect_creator = ConnectCreator(
            logger, self.config, self.openssl_context, self.host_manager)


        self.ip_manager = IpManager(
            logger, self.config, check_local_network,            
            None,
            os.path.join(data_path, "good_ip.txt"),
            scan_ip_log=None)

        #self.appid_manager.check_api = self.ip_checker.check_ip
        self.appid_manager.ip_manager = self.ip_manager

        self.connect_manager = ConnectManager(
            logger,
            self.config,
            self.connect_creator,
            self.ip_manager,
            check_local_network)

        self.http_dispatcher = HttpsDispatcher(
            logger, self.config, self.ip_manager, self.connect_manager
        )



    def request(
            self,
            method,
            host,
            path="/",
            headers={},
            data="",
            timeout=120):
        response = self.http_dispatcher.request(
            method, host, path, dict(headers), data, timeout=timeout)

        return response

    def stop(self):
        logger.info("terminate")
        self.connect_manager.set_ssl_created_cb(None)
        self.http_dispatcher.stop()
        self.connect_manager.stop()
        self.ip_manager.stop()

        self.running = False


front = Front()


class DirectFront(object):
    name = "direct_front"

    def __init__(self):
        pass

    def start(self):
        self.running = True

        self.host_manager = HostManager(front.config, logger)

        ca_certs = "cacert.pem"
        self.openssl_context = SSLContext(
            logger,
            ca_certs=ca_certs,
            support_http2=False,
            cipher_suites=[
                'ALL',
                "!RC4-SHA",
                "!ECDHE-RSA-RC4-SHA",
                "!ECDHE-RSA-AES128-GCM-SHA256",
                "!AES128-GCM-SHA256",
                "!ECDHE-RSA-AES128-SHA",
                "!AES128-SHA"])

        self.connect_creator = ConnectCreator(
            logger, front.config, self.openssl_context, self.host_manager)

        self.ip_manager = front.ip_manager
        self.connect_manager = ConnectManager(
            logger,
            front.config,
            self.connect_creator,
            self.ip_manager,
            check_local_network)

        self.dispatchs = {}

    def get_dispatcher(self, host):
        if host not in self.dispatchs:
            http_dispatcher = HttpsDispatcher(
                logger, front.config, front.ip_manager, self.connect_manager)
            self.dispatchs[host] = http_dispatcher

        return self.dispatchs[host]

    def request(self, method, host, path="/", headers={}, data="", timeout=60):
        dispatcher = self.get_dispatcher(host)

        response = dispatcher.request(
            method, host, path, dict(headers), data, timeout=timeout)

        return response

    def stop(self):
        logger.info("terminate")
        self.connect_manager.set_ssl_created_cb(None)
        for host in self.dispatchs:
            dispatcher = self.dispatchs[host]
            dispatcher.stop()
        self.connect_manager.stop()

        self.running = False


direct_front = DirectFront()
