'''
    Python3 bindings for scanmem for use with sm_globals and sm_execcomand
    Copyright (C) 2018 Justas Dabrila <justasdabrila@gmail.com>

    This library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this library.  If not, see <http://www.gnu.org/licenses/>.
'''

from ctypes import *
import ctypes.util
import atexit

libfile = ctypes.util.find_library("scanmem")

if libfile is None:
    raise OSError("Failed to find scanmem shared object.")

# backend initialization
backend = CDLL(libfile)

backend.sm_backend_exec_cmd.argtypes= [c_char_p]

backend.sm_init.restype             = c_bool
backend.sm_backend_exec_cmd.restype = c_bool

is_cleaned_up = True

# API
@atexit.register
def cleanup():
    global is_cleaned_up

    if not is_cleaned_up:
        is_cleaned_up = True
        backend.sm_cleanup()

def init():
    retval = backend.sm_init()

    if retval:
        global is_cleaned_up

        backend.sm_set_backend()
        is_cleaned_up = False

    return retval

def cmd(cmd):
    backend.sm_backend_exec_cmd(cmd.encode('ascii'))
