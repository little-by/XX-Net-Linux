#!/usr/bin/env python2
# coding:utf-8
# Based on GAppProxy 2.0.0 by Du XiaoGang <dugang.2008@gmail.com>
# Based on WallProxy 0.4.0 by Hust Moon <www.ehust@gmail.com>
# Contributor:
#      Phus Lu           <phus.lu@gmail.com>
#      Hewig Xu          <hewigovens@gmail.com>
#      Ayanamist Yang    <ayanamist@gmail.com>
#      V.E.O             <V.E.O@tom.com>
#      Max Lv            <max.c.lv@gmail.com>
#      AlsoTang          <alsotang@gmail.com>
#      Christopher Meng  <cickumqt@gmail.com>
#      Yonsm Guo         <YonsmGuo@gmail.com>
#      Parkman           <cseparkman@gmail.com>
#      Ming Bai          <mbbill@gmail.com>
#      Bin Yu            <yubinlove1991@gmail.com>
#      lileixuan         <lileixuan@gmail.com>
#      Cong Ding         <cong@cding.org>
#      Zhang Youfu       <zhangyoufu@gmail.com>
#      Lu Wei            <luwei@barfoo>
#      Harmony Meow      <harmony.meow@gmail.com>
#      logostream        <logostream@gmail.com>
#      Rui Wang          <isnowfy@gmail.com>
#      Wang Wei Qiang    <wwqgtxx@gmail.com>
#      Felix Yan         <felixonmars@gmail.com>
#      QXO               <qxodream@gmail.com>
#      Geek An           <geekan@foxmail.com>
#      Poly Rabbit       <mcx_221@foxmail.com>
#      oxnz              <yunxinyi@gmail.com>
#      Shusen Liu        <liushusen.smart@gmail.com>
#      Yad Smood         <y.s.inside@gmail.com>
#      Chen Shuang       <cs0x7f@gmail.com>
#      cnfuyu            <cnfuyu@gmail.com>
#      cuixin            <steven.cuixin@gmail.com>



import sys
import os

current_path = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.abspath(os.path.join(current_path, os.pardir,'data'))

import traceback
import platform

__file__ = os.path.abspath(__file__)
work_path = os.path.dirname(os.path.abspath(__file__))
os.chdir(work_path)

from logger import logger

from cert_util import CertUtil
import simple_http_server
import proxy_handler
#import env_info
from front import front, direct_front


proxy_server = None
# launcher/module_init will check this value for start/stop finished
ready = False


def log_info():
    logger.error('------------------------------------------------------')
    #logger.error('Python Version     : %s', platform.python_version())
    logger.error('Python Version     : %s', sys.version[:6])
    #logger.error('OS                 : %s', env_info.os_detail())
    logger.error('Listen Address     : %s:%d', front.config.listen_ip, front.config.listen_port)
    if len(front.config.GAE_APPIDS):
        logger.error('GAE APPID          : %s', '|'.join(front.config.GAE_APPIDS))
    else:
        logger.error("Using public APPID")
    logger.error('------------------------------------------------------')


def main(args):
    global ready, proxy_server

    log_info()

    CertUtil.init_ca()

    allow_remote = args.get("allow_remote", 0)

    listen_ips = front.config.listen_ip
    if isinstance(listen_ips, basestring):
        listen_ips = [listen_ips]
    else:
        listen_ips = list(listen_ips)
    if allow_remote and ("0.0.0.0" not in listen_ips or "::" not in listen_ips):
        listen_ips.append("0.0.0.0")
    addresses = [(listen_ip, front.config.listen_port) for listen_ip in listen_ips]

    front.start()
    direct_front.start()

    proxy_server = simple_http_server.HTTPServer(
        addresses, proxy_handler.GAEProxyHandler, logger=logger)

    ready = True  # checked by launcher.module_init
    
    proxy_server.serve_forever()


# called by launcher/module/stop
def terminate():
    global ready, proxy_server

    logger.error("start to terminate GAE_Proxy")
    ready = False
    front.stop()
    direct_front.stop()
    proxy_server.shutdown()


if __name__ == '__main__':
    try:
        main({})
    except Exception:
        traceback.print_exc(file=sys.stdout)
    except KeyboardInterrupt:
        terminate()
        sys.exit()
