from distutils.core import setup
import py2exe

setup(
	options = {'py2exe': {'bundle_files': 1, 'compressed': True}},
    windows = ['run.py','shadowsocks/local.py'],
    zipfile = None,
)