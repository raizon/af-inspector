#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Maxim Levitskiy
# Mail: mlevitskiy@ptsecurity.com
# Positive Technologies Support

import platform
from datetime import *
import re
import operator
import tools
import messages
import severites
import sys
import os
import locale
import threading
import webber
import argparse
from file_read_backwards import FileReadBackwards
from contextlib import contextmanager

path = os.getcwd()
sys.path.insert(1, '{}/modules'.format(path))


path = os.path.dirname(os.path.abspath(__file__))
tmp = '{}/temp'.format(path)

LOCALE_LOCK = threading.Lock()

host_system = platform.system()

services = {
             'monit': 'monit.log',
             'celery': 'worker1.log',
             'wafd': 'wafd.log',
             'waf-gowaf': 'waf-gowaf.log',
             'waf-correlator': 'waf-correlator.log',
             'trainer': 'trainer.log',
             'syslog': 'syslog',
             'diamond': 'diamond.log',
             'celerybeat': 'celerybeat.log',
             'nginx': 'nginx/error.log',
             'waf-sync': 'waf-sync.log',
             'ui': 'ui.log',
             'waf-api': 'waf_api.log',
             'waf-nginx': 'waf/error.log'
            }

parse_configs = ['monit', 'waf-nginx', 'wafd', 'waf-correlator',
                 'waf-gowaf', 'celery', 'celerybeat', 'trainer',
                 'syslog', 'diamond']


@contextmanager
def setlocale(name):
    with LOCALE_LOCK:
        saved = locale.setlocale(locale.LC_ALL)
        try:
            yield locale.setlocale(locale.LC_ALL, name)
        finally:
            locale.setlocale(locale.LC_ALL, saved)


locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')


def incoming(data, flags, mode='gui', test=False):
    if test is False:
        tools.clean(tmp)
        tools.process_content(tmp, data)
    candidates = {}
    filelist = tools.find_files(tmp, '.log')
    for filepath in filelist:
        for logfilename in services.values():
            if str(filepath).endswith(logfilename):
                for service_name, value in services.items():
                    if value == logfilename:
                        if service_name in flags:
                            candidates.update({service_name: filepath})
    raw = inspector(candidates)
    webber.page(path, mode)
    webber.errors_parser(raw, path, mode, filelist)
    webber.close(path, mode)
    if mode == 'web':
        return 0
    if host_system == 'Darwin':
        os.system("open '{}/report.html'".format(path))
    if host_system == 'Windows':
        os.system("'{}/report.html'".format(path))


# Сервис инспектора
def inspector(candidates):
    errors = {}
    for service in candidates.keys():
        filename = candidates.get(service)
        output = reader(service=service, filename=filename)
        if output != 0:
            b = sorter(service, output)
            errors.update({service: b})
            errors.get(service).update({'total_errors': output.get('total_errors')})
    return errors


def reader(filename, service, delta=24):
    print('читаю файл {}'.format(filename))
    error_marker = '(error|ERROR|Error|failed|crit|Unable)'
    total_errors = 0
    output = {}
    message_buffer = []
    message = []
    last_error = {}
    counter = {}
    errors = []
    flag = None
    with FileReadBackwards('{}'.format(filename), encoding="utf-8") as frb:
        for line in frb:

            # Захват сообщения из нескольких строк
            if time_catcher(line, service='{}'.format(service)) == 0:
                message_buffer.insert(0, line)

            # Если время удалось захватить
            else:
                # Проверяем доступно ли время последней записи
                if flag is None:
                    flag = 1
                    last_line_time = time_catcher(line, service='{}'.format(service))

                # Пытаемся захватить время
                line_time = time_catcher(line, service='{}'.format(service))
                timelock = last_line_time - timedelta(hours=delta)

                # Если время н строке больше чем максимально возможное ( 24 часа )
                if line_time > timelock:

                    # Если сообщение в буфере не ошибка - очищаем буфер
                    if len(re.findall(error_marker, line)) < 1:
                        message_buffer = []
                        continue

                    else:

                        message_buffer.insert(0, line)
                        message = "".join(message_buffer)

                        if len(re.findall('debug', message)) > 0:
                            continue

                        message = prepare(message, service)

                        if message == 'pass':
                            continue

                        if message in errors:
                            # Если ошибка есть, то добавляем к ее счетчику +1 и переходим к след линии
                            counter.update({'{}'.format(message): int(counter.get(message)) + 1})
                            total_errors += 1
                            message_buffer = []
                            pass
                        else:
                            # Создаем пару {Сообщение : время ошибки} и записываем в словарь last_error
                            last_error.update({'{}'.format(message): '{}'.format(line_time)})
                            # Создаем пару {Сообщение : колличество ошибок} и записываем в словарь counter
                            counter.update({'{}'.format(message): 1})
                            # Добавляем ошибку в список найденных ошибок
                            errors.append(message)
                            message_buffer = []
                            total_errors += 1
                else:
                    break
    if len(counter) == 0:
        return 0
    else:
        output.update({'total_errors': sum(counter.values())})
        output.update({'counter': counter})
        output.update({'last_error': last_error})
        output.update({'time_on_last_line': last_line_time})
        return output


# def sorter(errors, last_error, last_line_time, service):
def sorter(service, data):
    output = {}
    output.update({'log': data.get('log')})
    paper = []
    high = []
    mid = []
    low = []
    high_errors = []
    high_errors_counter = 0
    mid_errors = []
    mid_errors_counter = 0
    low_errors = []
    low_errors_counter = 0
    container = []
    for key in data.get('counter'):
        value = data.get('counter').get(key)
        container.append([key, value])
    sorted_container = sorted(container, key=operator.itemgetter(1), reverse=True)
    p = len(container)
    for error in sorted_container:
        p -= 1
        severity = severites.kb(error=error[0], service=service)
        if severity == 1:
            high.append(error)
        elif severity == 2:
            mid.append(error)
        else:
            low.append(error)
        if p == 0:
            continue
    if len(high) != 0:
        paper.append('<h4>\n\t Серьезные ошибки:\n</h4>')
        for error in high:
            high_errors.append(printer(error=[error[0], error[1]], last_error=data.get('last_error').get(error[0]), last_line_time=data.get('time_on_last_line')))
            high_errors_counter = high_errors_counter + int(error[1])
    if len(mid) != 0:
        paper.append('\n\t Средние ошибки:\n')
        for error in mid:
            mid_errors.append(printer(error=[error[0], error[1]], last_error=data.get('last_error').get(error[0]), last_line_time=data.get('time_on_last_line')))
            mid_errors_counter = mid_errors_counter + int(error[1])
    if len(low) != 0:
        paper.append('\n\t Незначительные ошибки:\n')
        for error in low:
            low_errors.append(printer(error=[error[0], error[1]], last_error=data.get('last_error').get(error[0]), last_line_time=data.get('time_on_last_line')))
            low_errors_counter = low_errors_counter + int(error[1])
    output.update({'high_errors': high_errors})
    output.update({'mid_errors': mid_errors})
    output.update({'low_errors': low_errors})
    output.update({'counters': {}})
    output.get('counters').update({'high_errors_counter': high_errors_counter})
    output.get('counters').update({'mid_errors_counter': mid_errors_counter})
    output.get('counters').update({'low_errors_counter': low_errors_counter})
    return output


#
def printer(error, last_error, last_line_time):
    # print error
    output = []
    if last_error == 0:
        output.append('x{} {}'.format(error[1], error[0]))
        return output
    delta = tools.splitter(str(last_line_time - datetime.strptime(last_error, "%Y-%m-%d %H:%M:%S")), ':')
    if int(delta[0]) == 0:
        output.append('<p>x{} {} - [{} мин. {} сек назад]</p>'.format(error[1], error[0], int(delta[1]), int(delta[2])))
    else:
        output.append('<p>x{} {} - [{} ч. {} мин. назад]</p>'.format(error[1], error[0], int(delta[0]), int(delta[1])))
    return output


# Захватить время в строке журналов
def time_catcher(string, service):
    with setlocale('C'):
        if service == 'monit':
            # Формат поиска времени - Jul 4 04:00:00
            a = re.findall(r'\w{3}[\s]+\d+\s+\d{2}:\d{2}:\d{2}', string)
            # re.findall возвращает 0 если ничего не нашел, следовательно, мы можем продолжать только если $a > 0
            if len(a) > 0:
                # Нормализуем $a - Извлекаем из списка, добавляем пробел и текущий год
                a = a[0] + ' ' + str(datetime.now().year)
                # Захватываем время по формату - Jul 4 04:00:00 2020
                t = datetime.strptime(a, "%b %d %H:%M:%S %Y")
                # Возвращаем время в формате Python
                return t
        if service == 'celery' or service == 'waf-sync':
            # Формат поиска времени - 2020-07-13 22:30:15
            a = re.findall(r'\d{4}-\d{2}-\d{2}\s[\d:]+', string)
            # re.findall возвращает 0 если ничего не нашел, следовательно, мы можем продолжать только если $a > 0
            if len(a) > 0:
                # Нормализуем $a - Извлекаем из списка, добавляем пробел и текущий год
                a = a[0]
                # Захватываем время по формату - 2020-07-13 22:30:15
                t = datetime.strptime(a, "%Y-%m-%d %H:%M:%S")
                # Возвращаем время в формате Python
                return t
        if service == 'waf-nginx-workers':
            a = re.findall(r'(\w{3}[\s]+\d+\s+\d{2}:\d{2}:\d{2}\s\d{4})', string)
            if len(a) == 0:
                return 0
            t = datetime.strptime(a[0], "%b %d %H:%M:%S %Y")
            return t
        if service == 'wafd':
            a = re.findall(r'\d{8}\s\d{2}:\d{2}:\d{2}', string)
            if len(a) == 0:
                return 0
            t = datetime.strptime(a[0], "%Y%m%d %H:%M:%S")
            return t
        if service == 'waf-gowaf':
            a = re.findall(r'\d{4}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2}', string)
            if len(a) == 0:
                return 0
            t = datetime.strptime(a[0], "%Y/%m/%d %H:%M:%S")
            return t
        if service == 'waf-correlator':
            a = re.findall(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}', string)
            if len(a) == 0:
                return 0
            t = datetime.strptime(a[0], "%Y-%m-%d %H:%M:%S")
            return t
        if service == 'trainer':
            a = re.findall(r'\d{4}\d{2}\d{2}\s\d{2}:\d{2}:\d{2}', string)
            if len(a) == 0:
                return 0
            t = datetime.strptime(a[0], "%Y%m%d %H:%M:%S")
            return t
        if service == 'syslog':
            a = re.findall(r'\w{3}[\s]+\d+\s+\d{2}:\d{2}:\d{2}', string)
            if len(a) > 0:
                # Нормализуем $a - Извлекаем из списка, добавляем пробел и текущий год
                a = a[0] + ' ' + str(datetime.now().year)
                # Захватываем время по формату - Jul 4 04:00:00 2020
                t = datetime.strptime(a, "%b %d %H:%M:%S %Y")
                # Возвращаем время в формате Python
                return t
        if service == 'diamond':
            a = re.findall(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}', string)
            if len(a) == 0:
                return 0
            t = datetime.strptime(a[0], "%Y-%m-%d %H:%M:%S")
            return t
        if service == 'celerybeat':
            a = re.findall(r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}', string)
            if len(a) == 0:
                return 0
            t = datetime.strptime(a[0], "%Y-%m-%d %H:%M:%S")
            return t
        if service == 'waf-nginx' or service == 'nginx':
            a = re.findall(r'\d{4}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2}', string)
            if len(a) == 0:
                return 0
            t = datetime.strptime(a[0], "%Y/%m/%d %H:%M:%S")
            return t
        else:
            return 0


# Разделитель линий для разных журналов
def prepare(line, service):
    if service == 'monit':
        message = tools.splitter(line, '  : ', output='value', position=1)
        message = messages.monit(message)
        return message
    if service == 'celery':
        message = tools.splitter(line, r':\s[/\w-]+\] ', output='value', position=1)
        message = messages.celery(message)
        return message
    if service == 'wafd':
        message = tools.splitter(line, r'[ero]{5}\s', output='value', position=1)
        message = messages.wafd(message)
        return message
    if service == 'waf-gowaf':
        if len(re.findall('warning', line)) > 0:
            return 'pass'
        if len(re.findall('info', line)) > 0:
            return 'pass'
        message = tools.splitter(line, r'[ero]{5}]\s', output='value', position=1)
        message = messages.waf_gowaf(message)
        return message
    if service == 'waf-correlator':
        message = tools.splitter(line, r']\s', output='value', position=1)
        message = messages.waf_correlator(message)
        return message
    if service == 'trainer':
        message = tools.splitter(line, r'[ero]{5}\s', output='value', position=1)
        message = messages.waf_trainer(message)
        return message
    if service == 'syslog':
        message = tools.splitter(line, r'\w{3}[\s]+\d+\s+\d{2}:\d{2}:\d{2}\s[\w+-]+\s', output='value', position=1)
        message = messages.syslog(message)
        return message
    if service == 'diamond':
        message = tools.splitter(line, r'\d+\]\s', output='value', position=1)
        message = messages.diamond(message)
        return message
    if service == 'celerybeat':
        message = tools.splitter(line, r']\s', output='value', position=1)
        message = messages.celerybeat(message)
        return message
    if service == 'waf-nginx':
        message = tools.splitter(line, r'[\[\w+\]]+\s\d+#\d+:\s', output='value', position=1)
        message = messages.waf_nginx(message)
        return message
    if service == 'nginx':
        message = tools.splitter(line, r'[\[\w+\]]+\s\d+#\d+:\s', output='value', position=1)
        message = messages.nginx(message)
        return message
    else:
        return 0


if __name__ == '__main__':
    # Захват аргументов
    parser = argparse.ArgumentParser(description='PT AF Inspector engine')
    parser.add_argument('-p', action='store', help='Адрес папки с журналами')
    # Инициализиурем переданные аргументы
    args = parser.parse_args()
    incoming(args.p, parse_configs, mode='web')

