#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
# Autor: Maxim Levitskiy
# Mail: mlevitskiy@ptsecurity.com
# Positive Technologies Support


import os
import re
import sys
from datetime import *
import shutil


log_file = 'inspector.log'
auth = '--authenticationDatabase admin -u root -p $(cat /opt/waf/conf/master_password)'


# Разделитель
def splitter(variable, symbol, output='list', position='0'):
    a = re.split(r'{}'.format(symbol), variable)
    if output == 'list':
        return a
    elif output == 'value':
        # Переводим строку в число
        p = int(position)
        # Выхватываем нужное значение
        a = a[p]
        return a


# Записываем данные в журнал
def logger(message, level='INFO ', display=False):
    # Определяем формат журнала
    timelock = datetime.now()
    line = '{} {}  {}'.format(timelock.strftime("%d-%m-%Y %H:%M:%S"), level, message)
    # открываем обрезаемый файл на запись в виде переменной f
    with open(log_file, 'a') as f:
        # Пишем линию
        f.write(line)
        # Печатаем символ переноса строки
        f.write('\n')
    if display:
        print(line)
    return line


# Работа с архивами
def tar(action, source, destanation):
    if action == 'extract':
        command = 'tar -xvf "{}" -C "{}" '.format(source, destanation)
        r = os.popen(command).readlines()
    if action == 'compress':
        r = os.popen('tar cvzf "{}" "{}" 2>/dev/null'.format(source, destanation)).readlines()
    return r


# Создаем директории
def makedirs(workspace, folder):
    path = os.path.join(workspace, folder)
    if not os.path.exists(path):
        os.makedirs(path)


# Удаляем старые файлы
def retention(directory, filetype, files_to_keep=5):
    # Сортируем фильтрованный по расширению файла список по возрастанию
    archives = sorted(filter(lambda x: x.endswith('{}'.format(filetype)), os.listdir(directory)))
    # Сравниваем колличество архивов с политикой хранения
    if len(archives) > files_to_keep:
        # Получаем список файлов на удаление
        retention_list = archives[: len(archives) - files_to_keep]
        for file in retention_list:
            lock = os.path.join(os.path.abspath(os.path.dirname(directory)), file)
            os.remove(lock)


# Очистить экран
def clear_display():
    os.system('clear')


# Запрос решения от пользователя
def decidion(question, text='', clear=True):
    if clear:
        clear_display()
    if text:
        print('\n\n\t\t\t{}'.format(text))
    check = str(input("\n\n\t {}  (Y/N) : ".format(question))).lower().strip()
    try:
        if check[0] == 'y':
            return True
        elif check[0] == 'n':
            return False
        else:
            return decidion(text, question)
    except Exception as e:
        return decidion(text, question)


def clean(path):
    for c in os.listdir(path):
        full_path = os.path.join(path, c)
        if os.path.isfile(full_path):
            os.remove(full_path)
        else:
            shutil.rmtree(full_path)


def find_files(folder, pattern):
    log_files = []
    for root, dirs, files in os.walk(folder):
        if isinstance(pattern, list):
            for extension in pattern:
                for file in files:
                    if file.endswith(extension):
                        log_files.append(os.path.join(root, file))
        else:
            for file in files:
                if file.endswith(pattern):
                    log_files.append(os.path.join(root, file))
    return log_files


def process_content(folder, obj):
    if str(obj).endswith('tar.gz') or str(obj).endswith('tar'):
        tar('extract', obj, folder)
    elif str(obj).endswith('zip'):
        os.popen('unzip "{}" -d "{}"'.format(obj, folder)).readlines()
    return 0


def wget(link):
    string = splitter(splitter(os.popen('curl -Is {} | grep Location'.format(link)).readline(), ':\s', output='value', position='1'), '\n', output='value')
    filename = splitter(string, '/', output='value', position='6')
    os.system('wget {} -O /opt/inspector/downloads/{}'.format(link, filename))
    return filename


def check_localy(ticket_id):
    find = os.popen('find /mnt/overseer/Проблемы -type d -name {}'.format(ticket_id)).readline()
    if find:
        return splitter(find, '\n', output='value')
    else:
        return 0