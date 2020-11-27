# -*- coding: utf-8 -*-
# Author: Maxim Levitskiy
# Mail: mlevitskiy@ptsecurity.com
# Positive Technologies Support


import os
import engine
import tools
path = os.path.dirname(os.path.abspath(__file__))


style = """
<head>
<style>

*  {
    font-family: "Roboto", sans-serif;
}

body {
    background: #232526;  /* fallback for old browsers */
    background: -webkit-linear-gradient(to left, #343537, #232526);  /* Chrome 10-25, Safari 5.1-6 */
    background: linear-gradient(to left, #343537, #232526); /* W3C, IE 10+/ Edge, Firefox 16+, Chrome 26+, Opera 12+, Safari 7+ */
}

.header {
    display: block;
    border: 3px;
    margin-top: 15px;
    margin-right: 10px;
    margin-left: 10px;
    margin-bottom: 10px;

    background: #f85032;  /* fallback for old browsers */
    background: -webkit-linear-gradient(to left, #e73827, #f85032);  /* Chrome 10-25, Safari 5.1-6 */
    background: linear-gradient(to left, #e73827, #f85032); /* W3C, IE 10+/ Edge, Firefox 16+, Chrome 26+, Opera 12+, Safari 7+ */

    border-radius: 0px;
    padding: 7px;
    color: white;
    /*outline: none;*/
    width: 130px;
    font-size: 13px;
    /*text-transform: uppercase;*/
    font-weight: bold;
    /*cursor: pointer;*/

}

details:not([open]) summary small {
    display: none;
    margin: 2px;
}

details[open] summary small {
    margin-left: 5px;
    color: gray;
}

.messages_high {
    display: block;
    border: 3px;
    margin-top: 8px;
    margin-right: 10px;
    margin-left: 10px;
    margin-bottom: 10px;
    background: #f85032;  /* fallback for old browsers */
    background: -webkit-linear-gradient(to left, #e73827, #f85032);  /* Chrome 10-25, Safari 5.1-6 */
    background: linear-gradient(to left, #e73827, #f85032); /* W3C, IE 10+/ Edge, Firefox 16+, Chrome 26+, Opera 12+, Safari 7+ */
    border-radius: 10px;
    padding: 7px;
    color: white;
    width: auto;
    font-size: 13px;
    font-weight: bold;
    cursor: text;
}
.messages_mid {
    display: block;
    border: 3px;
    margin-top: 8px;
    margin-right: 10px;
    margin-left: 10px;
    margin-bottom: 10px;
    background: #f12711;  /* fallback for old browsers */
    background: -webkit-linear-gradient(to bottom, #f57119, #f15f11);  /* Chrome 10-25, Safari 5.1-6 */
    background: linear-gradient(to bottom, #f57119, #f15f11); /* W3C, IE 10+/ Edge, Firefox 16+, Chrome 26+, Opera 12+, Safari 7+ */
    border-radius: 10px;
    padding: 7px;
    color: white;
    width: auto;
    font-size: 13px;
    font-weight: bold;
    cursor: text;
}
.messages_low {
    display: block;
    border: 3px;
    margin-top: 8px;
    margin-right: 10px;
    margin-left: 10px;
    margin-bottom: 10px;
    background: #1e3c72;  /* fallback for old browsers */
    background: -webkit-linear-gradient(to bottom, #2a5298, #1e3c72);  /* Chrome 10-25, Safari 5.1-6 */
    background: linear-gradient(to bottom, #2a5298, #1e3c72); /* W3C, IE 10+/ Edge, Firefox 16+, Chrome 26+, Opera 12+, Safari 7+ */
    border-radius: 10px;
    padding: 7px;
    color: white;
    width: auto;
    font-size: 13px;
    font-weight: bold;
    cursor: text;
}

.service {
    font-family: "DejaVu Sans";
    padding-top: 10px;
    display: block;
    font-size: 16px;
    color: #e3e3e3;
    cursor: pointer;
}

.filelink {
    text-decoration: none;
    font-family: "DejaVu Sans";
    padding-bottom: 5px;
    text-align: center;
    display: block;
    font-size: 15px;
    color: #e3e3e3;
    cursor: pointer;
    font-weight: bold;
}

.dirlink {
    text-decoration: none;
    font-family: "DejaVu Sans";
    padding-top: 25px;
    padding-left: 15px;
    text-align: left;
    display: block;
    font-size: 15px;
    color: #e3e3e3;
    cursor: pointer;
    font-weight: bold;
}

.box {
    display: block;
    border: 3px;
    margin-top: 18px;
    margin-right: 10px;
    margin-left: 10px;
    margin-bottom: 10px;
    background: #232526;  /* fallback for old browsers */
    background: -webkit-linear-gradient(to top, #222222, #2f2e2e);  /* Chrome 10-25, Safari 5.1-6 */
    background: linear-gradient(to top, #303030, #242424); /* W3C, IE 10+/ Edge, Firefox 16+, Chrome 26+, Opera 12+, Safari 7+ */
    border-radius: 10px;
    padding: 7px;
    color: white;
    width: auto;
    font-size: 13px;
    font-weight: bold;
    cursor: default;
    -webkit-box-shadow: inset 0px 0px 26px 19px rgba(0,0,0,0.74);
    box-shadow: inset 0px 0px 26px 19px rgba(26, 26, 26, 0.74);
}


.severity{
    cursor: default;
    margin-top: 5px;
    margin-left: 20px;
    margin-bottom: 5px;
    font-size: 14px;
}

p {
    font-family: "Courier New", Courier, monospace;
    font-size: 13px;
    /*letter-spacing: 2px;*/
    word-spacing: 2px;
    font-weight: normal;
    text-decoration: none;
    font-style: normal;
    font-variant: normal;
    text-transform: none;
    margin-top: -1px;
    margin-bottom: -1px;
}

</style>
</head>
\n
"""

flask_template = '/opt/inspector/templates/report.html'
flask_files = '/opt/inspector/templates/files.html'


def page(wrk_dir, mode):
    if mode == 'gui':
        with open('{}/report.html'.format(wrk_dir), 'w', encoding='utf-8') as f:
            f.write('<meta http-equiv="content-type" content="text-html; charset=utf-8">\n')
            f.write(style)
    if mode == 'web':
        with open(flask_template, 'w', encoding='utf-8') as f:
            f.write("{% extends 'base.html' %}")
            f.write("{% block title %}PT Application Firewall Log Inspector{% endblock %}")
            f.write("{% block body %}")


def errors_parser(content, wrk_dir, mode, filelist):
    if mode == 'web':
        filename = flask_template
    else:
        filename = '{}/report.html'.format(wrk_dir)

    with open(filename, 'a', encoding='utf-8') as f:

        if mode == 'gui':
            f.write('<div class="header">PT AF Log Inspector</div>\n')

        for service in content.keys():
            # Опрелеляем ссыылку на файл журнала
            # extension = engine.services.get(service)
            # for obj in filelist:
            #     if str(obj).endswith(extension):
            #         filelink = obj

            # Получаем список текущих ошибок для сервиса
            error_container = content.get(service)

            if error_container is None:
                continue

            # Добавляем пункт меню
            f.write('<details class="service">\n')
            f.write('<summary>{} - {}</summary>\n'.format(service, error_container.get('total_errors')))
            f.write('<div class="box">\n')

            if error_container.get('high_errors'):
                f.write('<div class="severity">Критические ошибки: {}</div>\n'.format(error_container.get('counters').get('high_errors_counter')))
                f.write('<div class="messages_high">\n')
                for message in error_container.get('high_errors'):
                    f.write('{}\n'.format(message[0]))
                f.write('</div>\n')

            if error_container.get('mid_errors'):
                f.write('<div class="severity">Серьезные ошибки: {}</div>\n'.format(error_container.get('counters').get('mid_errors_counter')))
                f.write('<div class="messages_mid">\n')
                for message in error_container.get('mid_errors'):
                    f.write('{}\n'.format(message[0]))
                f.write('</div>\n')

            if error_container.get('low_errors'):
                f.write('<div class="severity">Незначительные ошибки: {}</div>\n'.format(error_container.get('counters').get('low_errors_counter')))
                f.write('<div class="messages_low">\n')
                for message in error_container.get('low_errors'):
                    lenght = len(message[0])
                    if lenght > 210:
                        f.write('<p>-</p>\n')
                    f.write('{}\n'.format(message[0]))
                f.write('</div>\n')

            # f.write('<details class="service">\n')
            # f.write('<summary> Подробнее.. </summary>\n')
            # f.write('<div class="box">\n')
            # for n in error_container.get('log'):
            #     f.write('<p>{}</p>'.format(n))
            # f.write('</details>\n')
            # if mode == 'gui':
            #     f.write('<p><a class="filelink" href="{}"> Открыть файл журнала</a></p>'.format(filelink))
            f.write('</div>\n')
            f.write('</details>\n')
        # if mode == 'gui':
        #     f.write('<p><a class="dirlink" href="file:///{}"> Открыть директорию с журналами</a></p>'.format(tools.splitter(filelink, extension, output='value', position=0)))


def file_list(files):
    with open(flask_files, 'w', encoding='utf-8') as f:
        f.write("{% extends 'base.html' %}")
        f.write("{% block title %}PT Application Firewall Log Inspector{% endblock %}")
        f.write("{% block body %}")
        f.write('<p class="files_header"> В загрузках обнаружены архивы: </p>')
        for obj in files:
            f.write('<p class="files">{}</p>'.format(obj))
        f.write("{% endblock %}")


def close(wrk_dir, mode):
    if mode == 'gui':
        with open('{}/report.html'.format(wrk_dir), 'a', encoding='utf-8') as f:
            f.write('</body></html>')
    if mode == 'web':
        with open(flask_template, 'a', encoding='utf-8') as f:
            f.write("{% endblock %}")
