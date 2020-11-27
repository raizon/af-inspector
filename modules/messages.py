#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
# Author: Maxim Levitskiy
# Mail: mlevitskiy@ptsecurity.com
# Positive Technologies Support


import tools
import re


def len_control(prep, limit):
    limit += 1
    if len(prep) < limit:
        diff = limit - len(prep)
        while diff != 0:
            prep.append('0')
            diff = diff - 1
    return prep


def web_log_vars(message):
    container = {}
    sections = ['client', 'server', 'request', 'host', 'upstream']
    for s in sections:
        try:
            container.update({'{}'.format(s): tools.splitter(tools.splitter(message, '{}:'.format(s), output='value', position=1), ',', output='value', position=0)})
        except IndexError:
            pass
    return container


def wafd(message):
    prep = tools.splitter(message, ': ')
    prep = len_control(prep, 1)
    errors = {
        r"Snmpv3Sender:: check SNMPv3 settings.": 'Ошибка отправки по протоколу SNMPv3.'.format(prep[1]),
        r"ReplicaSetMonitor no master found for set: waf": '{}: Недоступен мастер-сервер базы данны Mongo'.format(prep[0]),
        r"0 oplog: can not get the cursor": '{}: Ошибка чтения данных из oplog'.format(prep[0]),
        r"dbclient": '{}: Подключение к базе данных'.format(prep[0]),
        r"[CONET_R] server \[127\.0\.0\.1\:27017": '{}: Ошибка подключения к базе данных Mongo'.format(prep[0])
    }
    for e in errors.keys():
        if re.findall(e, message):
            message = errors.get(e)
            return message
    return message


def celery(message):
    prep = tools.splitter(message, ': ')
    prep = len_control(prep, 1)
    errors = {
        r"Task\sexecute_one\[[\w-]+\]\sraised\sunexpected: [\w]+\('[\w]+',\)": 'Ошибка исполениия задачи - {}.'.format(prep[1]),
        r"(\[sentinel\] error code 39 received while checking feature [\d,\s]+)": 'pass'.format(prep[0]),
        r"(consumer: Cannot connect to amqp)": 'Ошибка подключения к сервису amqp.',
        r"would be larger than limit of": 'Недостаточный размер ElasticSearch Heap Size.'

    }
    for e in errors.keys():
        if re.findall(e, message):
            message = errors.get(e)
            return message
    if re.findall(r"waf_common.tasks.vulnerabilities.update_vulnerabilites_timestamps", message):
        prep = tools.splitter(message, 'unexpected:', output='value', position=1)
        name = tools.splitter(prep[0], '\'')
        message = 'Ошибка обновления уязвимостей - {}.'.format(prep)
        return message
    if re.findall(r"Max retries exceeded with url", message):
        ip = re.findall('[\d]+\.[\d]+\.[\d]+\.[\d]+', message)
        rule = tools.splitter(prep[2], '\s')
        message = 'Черный список - Дистигнуто максимальное попыток подключения к {} для скрипта {}.'.format(ip[0], rule[00])
        return message
    if re.findall(r"Connection to [\d]+\.[\d]+\.[\d]+\.[\d]+ timed out", message):
        ip = re.findall('[\d]+\.[\d]+\.[\d]+\.[\d]+', message)
        message = 'Таймут подлючения к {} скрипт - {}.'.format(ip[0], prep[1])
        return message
    else:
        return message


def monit(message):
    prep = len_control(tools.splitter(message, '\s'), 7)
    name = len_control(tools.splitter(prep[0], '\''), 2)
    errors = {
        "Monit": "pass",
        r"'ptaf' cpu wait usage of [\d.%]+ matches resource limit \[cpu wait usage > 40.0%\]": 'Время простоя в ожиданнии данных для обработки более 40%',
        "'nginx' failed to get service data": 'Ошибка при получении данных от сервиса UI',
        'memory_utilization': 'Высокая утилизация памяти системы',
        "'waf-nginx' total mem amount": 'Процесс waf-nginx потребляет слишком много памяти',
        "'ptaf' mem usage": 'Высокое потребление памяти',
        "'ptaf' loadavg": 'Высокая нагрузка на процессор',
        "'cpu_utilization' status failed": 'Высокая нагрузка на процессор',
        "'elasticsearch' service restarted": 'Служба elasticsearch часто перезпускается',
        "elasticsearch' failed protocol test": 'Ошибка проверки здоровья службы ElasticSearch',
        "Cannot create socket to \[127.0.0.1\]:9995": 'pass',
        "Event queue is full": 'pass',
        "Aborting event": 'pass',
        "Mail: Delivery failed": 'Ошибка при отправки почты',
        "'waf-sync' failed to stop": 'Ошибка остановки службы waf-sync',
        "HttpRequest: access denied -- client \[127.0.0.1\]: wrong password for user 'monit'": 'Неправильный пароль для пользователя monit',
        "Cannot open a connection to the mailserver": 'Ошибка при установки соединения с почтовым сервером {}'.format(prep[7]),
        r"Cannot create socket to \[\d+.\d+.\d+.\d+\]:\d+ -- No route to host": 'Не найден маршрут при создании сокета к узлу {}'.format(prep[4]),
        r"'[\w-]+' process is not running": 'Служба {} не запущена'.format(name[1]),
        r"'[\w-]+' failed to restart": 'Ошибка перезапуска службы {}'.format(name[1]),
        r"'[\w-]+' link down": '{} ошибка сетевого интерфейса'.format(name[1]),
        r"'health_check_token' status failed \([\d+]\) -- WARNING:root:\[sentinel\]": 'Ошибка проверки лицензии'.format(name[1]),
        r"'[\w-]+' status changed \(\d -> \d\)": 'pass',
        r"'[\w-]+' process is running after previous exec error": 'Служба {} запущена после предыдущей неудачной попытки'.format(name[1]),
        r"unmonitor": 'Служба {} снята с мониторинга'.format(name[1]),
        "29 times within 29 cycles": 'Служба {} неисправна'.format(name[1]),
        "is a zombie": 'Процесс {} службы {} - Зомби!'.format(prep[4], name[1]),
        "'[\w-]+' failed to start": 'Ошибка запуска службы {}'.format(name[1]),
        "'[\w-]+' start action failed": 'Ошибка запуска службы {}'.format(name[1]),
        "'[\w-]+' failed to restart": 'Ошибка перезапуска службы {}'.format(name[1]),
        "'[\w-]+' restart action failed": 'Ошибка перезапуска службы {}'.format(name[1]),
        "'[\w-]+' failed to stop": 'Ошибка остановки службы {}'.format(name[1]),
        "'[\w-]+' stop action failed": 'Ошибка остановки службы {}'.format(name[1]),
        "'[\w-]+' total mem amount of [\d\.]+% matches resource limit ": 'Служба {} превысила лимит оперативной памяти'.format(name[1]),
        "\'waf-sync\' failed protocol test \[HTTP\] at \[localhost\]\:9995 \[TCP\/IP\] -- Connection refused": 'Ошибка проверки здоровья службы waf-sync - подключение отклонено',
        "\'waf-nginx\' failed protocol test \[HTTP\] at \[localhost\]:18083 \[TCP\/IP\] -- HTTP\: Error receiving data -- Resource temporarily unavailable": 'Ошибка проверки здоровья службы waf-nginx - Resource temporarily unavailable',
        "\'waf-nginx\' failed protocol test \[HTTP\] at \[localhost\]:18083 \[TCP\/IP\] -- HTTP\: Error receiving data -- Interrupted system call": 'Ошибка проверки здоровья службы waf-nginx - Interrupted system call ',
        "\'waf-correlator\' failed protocol test \[HTTP\] at \[[\d+\S\-]+\]\:9900 \[TCP\/IP\] -- HTTP\: Error receiving data -- Resource temporarily unavailable": 'Ошибка проверки здоровья службы waf-correlator - Resource temporarily unavailable',
        "'[\w-]+' failed to get service data": 'Ошибка получения данных от службы {}'.format(name[1]),
    }
    for e in errors.keys():
        if re.findall(e, message):
            message = errors.get(e)
            return message
    if re.findall(r"'[\w-]+' status failed", message):
        info = tools.splitter(message, '--', output='value', position=1)
        prep = tools.splitter(message, '\s')
        name = tools.splitter(prep[0], '\'')
        message = 'Ошибка {} - {}'.format(name[1], info)
        return message
    if re.findall(r"'[\w-]+' failed to start -- could not start required services: '[\,\s\w-]+'", message):
        prep = tools.splitter(message, '\s')
        name = tools.splitter(prep[0], '\'')
        if len(prep) == 12:
            message = 'Ошибка запуска службы {} - не удалось запустить необходимые службы : {} {}'.format(name[1], prep[10], prep[11])
        elif len(prep) == 11:
            message = 'Ошибка запуска службы {} - не удалось запустить необходимую службу : {}'.format(name[1], prep[10])
        else:
            return message
    return message


def waf_correlator(message):
    prep = tools.splitter(message, '\s')
    prep = len_control(prep, 0)
    errors = {
        r"Unhandled error in Deferred:": 'Критическая ошибка службы коррелятора - Unhandled error in Deferred.',
        r"exceptions.UnicodeEncodeError: 'ascii' codec can't encode character": 'UnicodeEncodeError: \'ascii\' codec can\'t encode character',
        r"exceptions.AttributeError: 'NoneType' object has no attribute 'del_alert' ": 'exceptions.AttributeError: \'NoneType\' object has no attribute \'del_alert\'',
        r"twisted.internet.error.AlreadyCalled: Tried to cancel an already-called event.": "twisted.internet.error.AlreadyCalled: Tried to cancel an already-called event.",
        r"txes2.exceptions.SearchPhaseExecutionException: Failed to execute phase \[query\], all shards failed;": "Ошибка запроса данных из ElasticSearch - нет доступных шардов",
        r"Failure: twisted.internet.error.ConnectBindError: Couldn\'t bind: 24: Too many open files.": "Failure: twisted.internet.error.ConnectBindError: Too many open files.",
        r"txes2.exceptions.ElasticSearchException: ReduceSearchPhaseException\[Failed to execute phase \[fetch\].": "Ошибка получения данных из ElasticSearch.",
    }
    for e in errors.keys():
        if re.findall(e, message):
            message = errors.get(e)
            return message
    if re.findall(r"Failed to parse JSON", message):
        ticket_str = re.findall(r'"TICKET_ID"\:"[\w-]+"', message)
        ticket_id = tools.splitter(tools.splitter(ticket_str[0], '":"', output='value', position=1), '"', output='value', position=0)
        prep = tools.splitter(message, ': ')
        error = tools.splitter(prep[1], '\)', output='value', position=0)
        message = "Ошибка парсинга JSON - {} - ticket_id: {}".format(error, ticket_id)
        return message
    else:
        return message


def waf_trainer(message):
    prep = tools.splitter(message, r'type\s')
    prep = len_control(prep, 1)
    errors = {
        r"9001 socket exception \[CONNECT_ERROR\] server \[127.0.0.1:27017 \(127.0.0.1\) failed\]": 'Ошибка создания сокета для подключения к базе данных Mongo.',
        r"0 oplog: can not get the cursor": 'Ошибка чтения из oplog - can not get the cursor.',
        r"[\d]+ field not found, expected type 17": 'field not found - excpected type {}'.format(prep[1]),
        r"10278 dbclient": 'pass',
        r"socket exception \[SEND_ERROR\] for 192\.168\.200\.1:27017": 'Ошибка отправки отправки данных в базу данных Mongo.'
    }
    for e in errors.keys():
        if re.findall(e, message):
            message = errors.get(e)
            return message
    return message


def diamond(message):
    errors = {
        "URLError:": 'Collector failed - url open error',
        r"\[sentinel\] error code [\d]+ received while checking feature": 'pass',
        "nginx_status": 'Не удается получить статистику waf-nginx',
        "\:9200/_nodes/_local/stats\: \<urlopen error \[Errno": 'Ошибка подключения к сервису ElasticSearch'
    }
    for e in errors.keys():
        if re.findall(e, message):
            message = errors.get(e)
            return message
    return message


def celerybeat(message):
    errors = {
        r"RuntimeError": 'Ошибка службы',
        r"'Message Error: Couldn\'t apply scheduled task watchdog: \[Errno 111": 'Неудалось применить запланированную задачу watchdog'
    }
    for e in errors.keys():
        if re.findall(e, message):
            message = errors.get(e)
            return message
    return message


def waf_nginx(message):
    data = web_log_vars(message)
    errors = {
        r"127\.0\.0\.1\:16004": 'Ошибка передачи данных сервису wafd',
        r"upstream prematurely closed connection while reading response header from upstream": 'Апстрим закрыл соединение во время чтения заголовка - host:{}'.format(data.get('host')),
        r"upstream prematurely closed connection while reading upstream": 'Апстрим принудительно закрыл соединение во время получения данных - host:{}'.format(data.get('host')),
        r"upstream sent no valid HTTP/1\.0 header while reading response header from upstream": 'Апстрим отправил некоректный HTTP/1.0 заголовок - client:{}, host:{}, request:{}'.format(data.get('client'), data.get('host'), data.get('request')),
        r"Connection refused\) while connecting to upstream": 'Соединение отклонено во время попытки подключения к апстриму - host:{}'.format(data.get('server')),
        r"Connection reset by peer\) while reading response header from upstream": 'Подключение было сброшено клиентом во время чтения ответа от апстрима - client:{} server:{}'.format(data.get('client'), data.get('server')),
        r"writev\(\) failed \(32: Broken pipe\) while sending request to upstream": 'Внутренняя ошибка во время передачи запроса апстриму - {}, {}'.format(data.get('client'), data.get('server')),
        r"Network is unreachable\) while connecting to upstream": 'Невозможно установить соединение с апстримом. Cеть не доступна - {}, {}'.format(data.get('host'), data.get('server')),
        r"Connection reset by peer\) while connecting to upstream": 'Подключение сброшено клиентом во время подключения к апстриму - {}, {}'.format(data.get('host'), data.get('server')),
        r"Connection reset by peer\) while sending request to upstream": 'Подключение сброшено клиентом во время отправки запроса апстриму - {}, {}'.format(data.get('host'), data.get('server')),
        r"Connection reset by peer\) while proxying connection, client": 'Подключение сброшено клиентом во время проксирования запроса апстриму - {}, {}'.format(data.get('host'), data.get('server')),
        r"104\: Connection reset by peer\) while reading upstream": 'Подключение сброшено клиентом во время чтения ответа от апстрима - {}, {}'.format(data.get('host'), data.get('server')),
        r"Connection reset by peer\) while proxying upgraded connection": 'Connection reset by peer while proxying upgraded connection - {}, {}'.format(data.get('client'), data.get('server')),
        r"upstream timed out \(110: Connection timed out\)": 'Апстрим не ответчает - host:{}'.format(data.get('host')),
        r"no live upstreams while connecting to upstream": 'Не найдено работоспособных апстримов - host:{} server:{}'.format(data.get('host'), data.get('server')),
        r"inflate\(\)": 'Ошибка работы при сжатии контента - host:{} server:{}'.format(data.get('host'), data.get('server')),
        r"tls_process_client_hello:version too low": 'Ошибка рукопожатия - слишком старая версия клиента  - client:{} server:{}'.format(data.get('client'), data.get('server')),
        r"ssl3_write_pending\:bad write retry": 'Не удалось выполнить SSL_shutdown() - нарушена целостность запроса - client:{} server:{}'.format(data.get('client'), data.get('server')),
        r"routines\:ssl3_get_record\:packet length too long": 'Ошибка рукопожатия - packet length too long - client:{} server:{}'.format(data.get('client'), data.get('server')),
        r"SSL routines\:ssl3_read_bytes\:tlsv1 bad certificate status response": 'Ошибка рукопожатия - tlsv1 bad certificate status response - client:{} server:{}'.format(data.get('client'), data.get('server')),
        r"SSL routines\:ssl_bytes_to_cipher_list\:inappropriate fallback": 'Ошибка рукопожатия - inappropriate fallback - client:{} server:{}'.format(data.get('client'), data.get('server')),
        r"tls_process_client_hello\:unsupported protocol": 'Ошибка рукопожатия - неподдерживаемый протокол - client:{} server:{}'.format(data.get('client'), data.get('server')),
        r"ssl3_get_record:wrong version number\) while SSL handshaking to upstream": 'Ошибка рукопожатия с апстримом - wrong version number  - client:{} server:{}'.format(data.get('client'), data.get('server')),
        r"rule-engine\: error while applying policy filterlist": 'rule-engine: Ошибки применения фильтров политик - server:{}'.format(data.get('client'), data.get('server')),
        r"ngx-waf-mod-db\: can't read policy": 'ngx-waf-mod-db: Ошибка чтения политики из базы данных',
        r"wafcore\: can't load policy": 'wafcore: Ошибка загрузки политики',
    }
    for e in errors.keys():
        if re.findall(e, message):
            message = errors.get(e)
            return message
    if re.findall(r"Connection timed out\) while connecting to upstream", message):
        prep = tools.splitter(message, r',')
        x = re.findall('upstream', prep[5])
        if len(x) == 0:
            upstream = tools.splitter(prep[4], '/', output='value', position=2)
            message = 'Таймаут попытки подключения к апстриму - {}, upstream: "{}"'.format(prep[2], upstream)
            return message
        message = 'Таймаут подключения к апстриму - {}, {}'.format(prep[2], prep[5])
    return message


def nginx(message):
    data = web_log_vars(message)
    errors = {
        r"Connection refused\) while connecting to upstream": 'Соединение отклонено во время попытки подключения к апстриму - host:{}'.format(data.get('upstream')),
    }
    for e in errors.keys():
        if re.findall(e, message):
            message = errors.get(e)
            return message
    return message



def waf_gowaf(message):
    errors = {
        r"Error while monitoring oplog": 'Ошибка чтения данных из oplog.',
        r"Got \[terminated\]": 'Процесс go-waf завершен.'
    }
    for e in errors.keys():
        if re.findall(e, message):
            message = errors.get(e)
            return message
    return message


def syslog(message):
    prep = tools.splitter(message, ': ')
    prep = len_control(prep, 1)
    errors = {
        r"dispatch error reporting limit reached - ending report notification": 'dispatch error reporting limit reached - ending report notification.'.format(prep[1]),
        r"CIFS VFS\: Send error in SessSetup = -126": 'CIFS VFS: Send error in SessSetup = -126'.format(prep[0]),
        r"ERROR - Unhandled update exception": 'pyagentx.updater - Unhandled update exception.',
        r"waf-gowaf\[\d+\]: fatal error: concurrent map read and map write": 'Фатальная ошибка waf-gowaf - необходимо обновить бинарный файл'
    }
    for e in errors.keys():
        if re.findall(e, message):
            message = errors.get(e)
            return message
    return message


