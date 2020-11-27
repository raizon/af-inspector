#!/Library/Frameworks/Python.framework/Versions/3.7/bin/python3.7
# -*- coding: UTF-8 -*-
# Author: Maxim Levitskiy
# Mail: mlevitskiy@ptsecurity.com
# Positive Technologies Support

import wx
import engine
import webber
import os
import platform
import wx.html
import wx.html2
import locale
import tools

mode = 'gui'
TASK_RANGE = 50

path = os.path.dirname(os.path.abspath(__file__))
tmp = '{}/temp'.format(path)

host_system = platform.system()

# parse_configs = ['monit', 'waf-nginx']
parse_configs = ['monit', 'waf-nginx', 'wafd', 'waf-correlator', 'waf-gowaf', 'celery', 'celerybeat', 'trainer', 'syslog', 'diamond']

CONTENT = []

services = {'monit': 'monit.log',
            'celery': 'celery/worker1.log',
            'wafd': 'waf/wafd.log',
            'waf-gowaf': 'waf/waf-gowaf.log',
            'waf-correlator': 'waf/waf-correlator.log',
            'trainer': 'waf/trainer.log',
            'syslog': 'syslog',
            'diamond': 'diamond.log',
            'celerybeat': 'celerybeat/celerybeat.log',
            'waf-nginx': 'waf/error.log'}


with open('{}/data/last_dir'.format(path), 'r', encoding='utf-8') as f:
    LAST_DIR = f.read()


def wx_gui():
    # Next, create an application object.
    app = wx.App()
    # Then a frame.
    frm = HelloFrame(None, title="Inspector")
    # Show it.
    frm.Show()
    locale.setlocale(locale.LC_ALL, '')
    # Start the event loop.
    app.MainLoop()


def service_by_path(obj):
    filename = os.path.basename(obj)
    for serv in services.keys():
        if filename in services.get(serv):
            engine.incoming(obj, serv)


class HelloFrame(wx.Frame):
    """
    A Frame that says Hello World
    """

    def __init__(self, parent, *args, **kw):
        super().__init__(parent=None, title='PT AF Log Inspector', size=(650, 200))

        panel = wx.Panel(self)
        panel.SetBackgroundColour((35, 35, 35, 255))
        # hbox = wx.BoxSizer(wx.HORIZONTAL)

        self.text_ctrl = wx.TextCtrl(panel, pos=(20, 24), size=(430, 22))
        self.text_ctrl.SetBackgroundColour((240, 240, 240, 255))
        self.text_ctrl.SetForegroundColour((62, 62, 62, 255))

        self.choose_dir = wx.Button(panel, label='Обзор', pos=(460, 25))
        self.choose_dir.Bind(wx.EVT_BUTTON, self.on_open_folder)
        # self.choose_dir.SetForegroundColour((200, 200, 200, 255))

        self.start_button = wx.Button(panel, label='Запуск', pos=(550, 25))
        self.start_button.Bind(wx.EVT_BUTTON, self.on_press)
        # self.start_button.SetForegroundColour((40, 200, 40, 255))

        # self.description = wx.StaticText(panel, label='Обрабатывать только эти журналы', pos=(20, 40), size=(100, 50))
        # self.description.SetForeGroundColour((240, 240, 240, 255))
        # font = wx.Font(18, wx.ROMAN, wx.ITALIC, wx.NORMAL)
        # self.description.SetFont(font)

        lbl1 = wx.StaticText(panel, -1, label='Просмотреть журналы выборочно:', style=wx.ALIGN_LEFT | wx.ST_ELLIPSIZE_MIDDLE, pos=(30, 92), size=(300, 300))
        lbl1.SetForegroundColour((150, 150, 150))

        self.chk1 = wx.CheckBox(panel, pos=(310, 72), label='Monit')
        self.chk1.SetForegroundColour((190, 190, 190))

        self.chk2 = wx.CheckBox(panel, pos=(310, 102), label='waf-nginx')
        self.chk2.SetForegroundColour((190, 190, 190))

        self.chk3 = wx.CheckBox(panel, pos=(310, 132), label='wafd')
        self.chk3.SetForegroundColour((190, 190, 190))

        self.chk4 = wx.CheckBox(panel, pos=(410, 72), label='waf-correlator')
        self.chk4.SetForegroundColour((190, 190, 190))

        self.chk5 = wx.CheckBox(panel, pos=(410, 102), label='waf-gowaf')
        self.chk5.SetForegroundColour((190, 190, 190))

        self.chk6 = wx.CheckBox(panel, pos=(410, 132), label='celery')
        self.chk6.SetForegroundColour((190, 190, 190))

        self.chk7 = wx.CheckBox(panel, pos=(540, 72), label='trainer')
        self.chk7.SetForegroundColour((190, 190, 190))

        self.chk8 = wx.CheckBox(panel, pos=(540, 102), label='syslog')
        self.chk8.SetForegroundColour((190, 190, 190))

        self.chk9 = wx.CheckBox(panel, pos=(540, 132), label='diamond')
        self.chk9.SetForegroundColour((190, 190, 190))

        self.Show()
        # self.text_ctrl.SetValue('Укажите дирикторию с журналами')
        self.text_ctrl.SetValue(LAST_DIR)

    def on_open_folder(self, event):
        title = "Choose a directory:"
        dlg = wx.FileDialog(self, title, style=wx.DD_DEFAULT_STYLE)
        if dlg.ShowModal() == wx.ID_OK:
            # self.text_ctrl.SetValue(dlg.GetPath())
            self.text_ctrl.SetValue((dlg.GetPath()))
            with open('{}/data/last_dir'.format(path), 'w', encoding='utf-8') as f:
                f.write(dlg.GetPath())
        dlg.Destroy()

    def on_press(self, event):
        obj = self.text_ctrl.GetValue()

        # Если ничего не выбрано
        if not obj:
            print("You didn't enter anything!")
        else:

            # Если путь оканчивается на log
            if str(obj).endswith('.log'):
                service_by_path(obj)

            # если выбарано что-то другое
            with open('{}/data/last_dir'.format(path), 'w', encoding='utf-8') as f:
                f.write(self.text_ctrl.GetValue())
            jam = {}
            jam.update({'monit': self.chk1.GetValue()})
            jam.update({'waf-nginx': self.chk2.GetValue()})
            jam.update({'wafd': self.chk3.GetValue()})
            jam.update({'waf-correlator': self.chk4.GetValue()})
            jam.update({'waf-gowaf': self.chk5.GetValue()})
            jam.update({'celery': self.chk6.GetValue()})
            jam.update({'trainer': self.chk7.GetValue()})
            jam.update({'syslog': self.chk8.GetValue()})
            jam.update({'diamond': self.chk9.GetValue()})
            for s in parse_configs:
                a = jam.get(s)
                if a is True:
                    CONTENT.append(s)
            if len(CONTENT) == 0:
                for p in parse_configs:
                    CONTENT.append(p)
            engine.incoming(obj, CONTENT)
            CONTENT.clear()
            # os.system("open report.html")

            # class MyBrowser(wx.Dialog):
            #     def __init__(self, *args, **kwds):
            #         wx.Dialog.__init__(self, style=wx.DEFAULT_DIALOG_STYLE | wx.RESIZE_BORDER, *args, **kwds,)
            #         sizer = wx.BoxSizer(wx.VERTICAL)
            #         self.browser = wx.html2.WebView.New(self)
            #         sizer.Add(self.browser, 1, wx.EXPAND, 10)
            #         self.SetSizer(sizer)
            #         self.SetSize((700, 750))
            #         CONTENT.clear()
            #
            # app = wx.App()
            # dialog = MyBrowser(None, -1)
            # page = ''
            # with open('report.html', 'r', encoding='utf-8') as f:
            #     for s in f:
            #         page = page + s
            # dialog.browser.SetPage(page, '')
            # dialog.Show()
            # app.MainLoop()
