from infi.systray import SysTrayIcon
import ctypes
import win32gui
import win32api
import win32con;
import time

def try_click(systkray):
	global window_handle
	global is_window_visible
	is_window_visible= not is_window_visible
	win32gui.ShowWindow(window_handle , win32con.SW_SHOW if (is_window_visible) else win32con.SW_HIDE)

	
	

is_window_visible=False
window_handle = win32gui.GetForegroundWindow()

def on_quit_callback(systray):
    program.shutdown()

menu_options = (("Show/Hide", None, try_click),)
systray = SysTrayIcon("icon.ico", "Shs 1081 v2.1", menu_options,default_menu_index=0,on_quit=on_quit_callback)
systray.start()

while 1:
	print "SDSD"
	time.sleep(1)