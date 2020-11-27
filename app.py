from flask import Flask, render_template, url_for, request, redirect, Response
import sys
import os
import zipfile
import inspector
import engine
import re
import tools
import webber
from forms import set_data_form
import subprocess
import time





app = Flask(__name__)
parse_configs = ['monit', 'waf-nginx', 'wafd', 'waf-correlator',
                 'waf-gowaf', 'celery', 'celerybeat', 'trainer',
                 'syslog', 'diamond']
# parse_configs = ['diamond']


@app.route('/', methods=['POST', 'GET'])
def index():
    form = set_data_form()
    if form.validate_on_submit():
        req = request.form.get('incoming')

        if str(req).startswith('test'):
            # engine.incoming('/opt/inspector/modules/temp', parse_configs, mode='web', test=True)
            return render_template('report.html', form=form)

        if str(req).startswith('http'):
            filename = tools.wget(req)
            engine.incoming('/opt/inspector/downloads/{}'.format(filename), parse_configs, mode='web')
            # os.system('/usr/bin/python3 /opt/inspector/modules/engine.py -p "/opt/inspector/downloads/{}" -c "all"'.format(filename))
            return render_template('report.html', form=form)

        if str(req).startswith('/mnt'):
            engine.incoming(req, parse_configs, mode='web')
            return render_template('report.html', form=form)

        if re.findall(r'[\S]{3}-[\S]{3}-[\S]{5}', req):
            result = tools.check_localy(req)
            if result is not 0:
                webber.file_list(tools.find_files(result, ['zip', 'tar.gz', 'tar']))
                return render_template('files.html', form=form)

    return render_template('index.html', form=form)



@app.route('/report')
def report():
    return render_template('report.html')

app.config['SECRET_KEY'] = 'any secret string'

if __name__ == "__main__":
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(host='0.0.0.0')




