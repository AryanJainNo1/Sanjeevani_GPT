import os
import sys

# Get the path from cPanel's Python app configuration
VIRTUALENV = os.path.expanduser('~/virtualenv/your_app_root/3.9/root')
PYTHON_BIN = os.path.join(VIRTUALENV, 'bin/python3')

if sys.executable != PYTHON_BIN:
    os.execl(PYTHON_BIN, PYTHON_BIN, *sys.argv)

sys.path.insert(0, os.path.dirname(__file__))

from main import app as application