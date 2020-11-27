#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
# Autor: Maxim Levitskiy
# Mail: mlevitskiy@ptsecurity.com
# Positive Technologies Support


import tools
import re


def kb(error, service):
    if service == 'monit':
        return monit(error)
    if service == 'waf-correlator':
        return waf_correlator(error)
    if service == 'wafd':
        return wafd(error)
    if service == 'waf-gowaf':
        return waf_gowaf(error)
    if service == 'waf-nginx':
        return waf_nginx(error)
    if service == 'trainer':
        return trainer(error)
    if service == 'celery':
        return celery(error)
    if service == 'diamond':
        return diamond(error)
    else:
        return None


def diamond(error):
    high = ['15044']
    mid = ['waf-nginx', 'Ошибка подключения к сервису ElasticSearch']
    low = ['Collector failed - url open error']
    for h in high:
        if re.findall('{}'.format(h), error):
            return 1
    for m in mid:
        if re.findall('{}'.format(m), error):
            return 2
    for l in low:
        if re.findall('{}'.format(l), error):
            return 3
    return 3


def monit(error):
    high = ['handler-GW', 'Высокая утилизация памяти системы', 'waf-nginx', 'check_status_GW',
            'Высокая нагрузка на процессор', 'wafd', 'handler-DB', 'Высокое потребление памяти',
            'mongod', 'лицензии', 'c-icap', 'неисправна', 'снята с мониторинга', 'clamd не запущен',
            'waf-correlator не запущен', 'keepalived']
    mid = ['handler-UI', 'elasticsearch', 'waf-trainer', 'маршрут', 'celerybeat', 'taperedng',
           'tasks-control', 'celery', 'waf_api', 'wsc_api', 'wsc-daemon', 'waf-sync', 'waf-gowaf',
           'waf-correlator', 'лимит оперативной памяти', 'Ошибка проверки здоровья службы',
           'Служба waf-correlator запущена после предыдущей неудачной попытки', 'Время простоя в ожиданнии данных для обработки более 40%']
    low = ['autodiscover', 'Ошибка при установки соединения с почтовым сервером',
           'graphite', 'ptbbs-controller', 'ui', 'tproxy-automangle',
           'waf-correlator запущен после предыдущей неудачной попытки']
    for h in high:
        if re.findall('{}'.format(h), error):
            return 1
    for m in mid:
        if re.findall('{}'.format(m), error):
            return 2
    for l in low:
        if re.findall('{}'.format(l), error):
            return 3
    return 3


def waf_correlator(error):
    high = ['error.AlreadyCalled', 'error.ConnectBindError']
    mid = ['Ошибка парсинга JSON']
    low = []
    for h in high:
        if re.findall('{}'.format(h), error):
            return 1
    for m in mid:
        if re.findall('{}'.format(m), error):
            return 2
    for l in low:
        if re.findall('{}'.format(l), error):
            return 3
    return 3


def wafd(error):
    high = ['Mongo', 'oplog']
    mid = []
    low = []
    for h in high:
        if re.findall('{}'.format(h), error):
            return 1
    for m in mid:
        if re.findall('{}'.format(m), error):
            return 2
    for l in low:
        if re.findall('{}'.format(l), error):
            return 3
    return 3


def waf_gowaf(error):
    high = ['oplog']
    mid = ['Процесс go-waf завершен']
    low = []
    for h in high:
        if re.findall('{}'.format(h), error):
            return 1
    for m in mid:
        if re.findall('{}'.format(m), error):
            return 2
    for l in low:
        if re.findall('{}'.format(l), error):
            return 3
    return 3


def waf_nginx(error):
    high = ['Ошибка передачи данных сервису wafd', "wafcore: can't load policy", 'socket', 'ngx-waf-mod-db',
            "Ошибка чтения политики из базы данных",
            'wafcore']
    mid = ['Апстрим отправил некоректный', 'Соединение отклонено во время попытки подключения к апстриму',
           'Не найдено работоспособных апстримов', 'Таймаут попытки подключения к апстриму',
           'Апстрим не ответчает', 'Апстрим закрыл', 'Апстрим принудительно закрыл', 'hmm']
    low = []
    for h in high:
        if re.findall('{}'.format(h), error):
            return 1
    for m in mid:
        if re.findall('{}'.format(m), error):
            return 2
    for l in low:
        if re.findall('{}'.format(l), error):
            return 3
    return 3


def trainer(error):
    high = ['Mongo']
    mid = []
    low = ['Ошибка чтения из oplog - can not get the cursor.']
    for h in high:
        if re.findall('{}'.format(h), error):
            return 1
    for m in mid:
        if re.findall('{}'.format(m), error):
            return 2
    for l in low:
        if re.findall('{}'.format(l), error):
            return 3
    return 3


def celery(error):
    high = ['Heap', 'Дистигнуто максимальное попыток подключения']
    mid = ['Ошибка обновления уязвимостей', 'Таймут подлючения']
    low = []
    for h in high:
        if re.findall('{}'.format(h), error):
            return 1
    for m in mid:
        if re.findall('{}'.format(m), error):
            return 2
    for l in low:
        if re.findall('{}'.format(l), error):
            return 3
    return 3


