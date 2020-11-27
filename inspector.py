#!/usr/local/opt/python@3.7/bin/python3
# -*- coding: UTF-8 -*-
# Author: Maxim Levitskiy
# Mail: mlevitskiy@ptsecurity.com
# Positive Technologies Support


import sys
import os
import os.path

path = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(1, '{}/modules'.format(path))
import webber
import engine

# parse_configs = ['monit', 'waf-nginx']
parse_configs = ['monit', 'waf-nginx', 'wafd', 'waf-correlator', 'waf-gowaf', 'celery', 'trainer', 'syslog', 'diamond']

services = {
    'monit': 'monit.log',
    'celery': 'celery/worker1.log',
    'wafd': 'waf/wafd.log',
    'waf-gowaf': 'waf/waf-gowaf.log',
    'waf-correlator': 'waf/waf-correlator.log',
    'trainer': 'waf/trainer.log',
    'syslog': 'syslog',
    'diamond': 'diamond.log',
    'celerybeat': 'celerybeat/celerybeat.log',
    'waf-nginx': 'waf/error.log'
}

# content = []
content = ['monit', 'waf_nginx', 'wafd', 'waf-correlator', 'waf-gowaf', 'celery', 'trainer', 'syslog']


def start(mode='gui'):
    if mode == 'gui':
        import gui
        gui.wx_gui()
    if mode == 'web':
        wrk_dir = os.path.join(path, 'temp/logs')
        data = engine.inspector(content, services, wrk_dir)
        webber.page(path, mode)
        webber.errors_parser(content, data[0], path, data[1], mode)
        webber.close(path, mode)


if __name__ == '__main__':
    start(mode='gui')
