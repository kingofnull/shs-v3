#!/usr/bin/env python
# -*- coding: utf-8 -*-	
from __future__ import absolute_import, division, print_function, with_statement


import requests
import uuid
import os
import time

import sys
import logging
import signal

from infi.systray import SysTrayIcon
import ctypes
import win32gui
import win32api
import win32con;
import time





# sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))
from shadowsocks import shell, daemon, eventloop, tcprelay, udprelay, asyncdns

def getSetting():
	print ("getting setting ...")
	url="https://shadow.tunnelz.online/startShadowsocksSession"
	data={
	'sessionPasswordInput': uuid.uuid4().hex,
	'email': "",
	'userEmail': "",
	'email': "",
	'plan': "Occasional",
	'OccasionalTotal': "11.40",
	'OccasionalPerMonth': "3.80",
	'OccasionalTotalMonths': "3",
	'source': "PlansTable",
	'userEmail': "",
	'email': "",
	'plan': "Premium",
	'PremiumTotal': "13.50",
	'PremiumPerMonth': "4.50",
	'PremiumTotalMonths': "3",
	'source': "PlansTable"
	}
	# r=requests.post(url,data=data,proxies={"http"  : "https://212.237.30.203:8888"})
	r=requests.api.request('post', url, verify=False,data=data,proxies={"http"  : "https://212.237.30.203:8888"})
	
	result=r.json()
	shell="local.exe -s {} -p {} -k {}  -l 1081".format(result['sessionHost'],result['sessionPort'],result['sessionPassowrd'])
	print (shell)


	# config = shell.get_config(True)
	config={
	'server':result['sessionHost'].encode('ascii'),
	'server_port':int(result['sessionPort']),
	'password':result['sessionPassowrd'].encode('ascii'),	
	}
	
	return config


loop=None
tcp_server=None
udp_server=None
def init():
	global lastTime
	global loop
	global tcp_server
	global udp_server
	
	
	config={
	'server':'',
	'server_port':0,
	'password':'',	
	'local_address':'127.0.0.1',
	'local_port':1081,
	'method':'aes-256-cfb',
	'timeout':0,
	'fast_open':False,
	'workers':1,
	'verbose':True,
	'one_time_auth':False,
	'prefer_ipv6':False,
	'server_port':False
	}
	# shell.check_python()

	lastTime=(time.time())
	config.update(getSetting())

	# fix py2exe
	if hasattr(sys, "frozen") and sys.frozen in ("windows_exe", "console_exe"):
		p = os.path.dirname(os.path.abspath(sys.executable))
		os.chdir(p)


	# daemon.daemon_exec(config)
	logging.basicConfig(level=logging.INFO,
							format='%(asctime)s %(levelname)-8s %(message)s',
							datefmt='%Y-%m-%d %H:%M:%S')

	logging.info("starting local at %s:%d" %  (config['local_address'], config['local_port']))

	dns_resolver = asyncdns.DNSResolver()
	tcp_server = tcprelay.TCPRelay(config, dns_resolver, True)
	udp_server = udprelay.UDPRelay(config, dns_resolver, True)
	loop = eventloop.EventLoop()
	dns_resolver.add_to_loop(loop)
	tcp_server.add_to_loop(loop)
	udp_server.add_to_loop(loop)

	def handler(signum, _):
		logging.warn('received SIGQUIT, doing graceful shutting down..')
		tcp_server.close(next_tick=True)
		udp_server.close(next_tick=True)
	signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM), handler)

	def int_handler(signum, _):
		sys.exit(1)
	signal.signal(signal.SIGINT, int_handler)

	# daemon.set_user(config.get('user', None))

	def __tick():
		global lastTime
		if (time.time()-lastTime)>43200 :
			print ('updating connection ...')
			config.update(getSetting())
			lastTime=time.time()
			tcp_server.updateConfig(config)
			udp_server.updateConfig(config)
			
		

	loop.add_periodic(__tick)

	loop.run()


def try_click(systkray):
	global window_handle
	global is_window_visible
	is_window_visible= not is_window_visible
	win32gui.ShowWindow(window_handle , win32con.SW_SHOW if (is_window_visible) else win32con.SW_HIDE)

	
	

is_window_visible=False
window_handle = win32gui.GetForegroundWindow()
win32gui.ShowWindow(window_handle ,win32con.SW_HIDE)


def on_quit_callback(systray):
    sys.exit(1)

menu_options = (("Show/Hide", None, try_click),)
systray = SysTrayIcon("icon.ico", "Shs 1081 v2.1", menu_options,default_menu_index=0,on_quit=on_quit_callback)
systray.start()


while 1:
	try:
		init()
	except Exception as e: 
		print(e)
		time.sleep(1)
		if tcp_server:
			tcp_server.close(next_tick=True)
			tcp_server=None
			
		if tcp_server:
			udp_server.close(next_tick=True)
			udp_server=None
		
