#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import json

current_path = os.path.dirname(os.path.abspath(__file__))
data_path = os.path.abspath(os.path.join(current_path, os.pardir,'data'))
jsonfile = os.path.join(data_path, 'config.json')

config = sys.modules[__name__]

with file(jsonfile, 'r') as f:
    t = json.load(f)
for n in t:
    setattr(config, n, t[n])

setattr(config, 'CHECK_PKP', set(config.check_pkp))
setattr(config, 'HOSTS_GAE', tuple(config.hosts_gae))
setattr(config, 'HOSTS_DIRECT', tuple(config.hosts_direct))
setattr(config, 'HOSTS_GAE_ENDSWITH', tuple(config.hosts_gae_endswith))
setattr(config, 'HOSTS_DIRECT_ENDSWITH', tuple(config.hosts_direct_endswith))
setattr(config, 'GOOGLE_ENDSWITH', tuple(config.google_endswith))
setattr(config, 'br_sites', tuple(config.BR_SITES))
setattr(config, 'br_endswith', tuple(config.BR_SITES_ENDSWITH))
