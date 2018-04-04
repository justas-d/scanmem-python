'''
    Python3 bindings for scanmem
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

backend.sm_execcommand.argtypes = [c_void_p, c_char_p]
backend.sm_set_stop_flag.argtypes = [c_bool]

backend.sm_init.restype = c_bool
backend.sm_execcommand.restype = c_bool
backend.sm_get_num_matches.restype = c_ulong
backend.sm_get_version.restype = c_char_p
backend.sm_get_scan_progress = c_double


if not backend.sm_init():
    raise OSError("scanmem sm_init() failed.")

backend.sm_set_backend()

class GlobalOptions(Structure):
    _fields_ = [
            ("alignment", c_ushort),
            ("debug", c_ushort),
            ("backend", c_ushort),
            ("scan_data_type", c_uint), # scan_data_type_t
            ("region_scan_level", c_uint), #region_scan_level_t
            ("dump_with_ascii", c_ushort),
            ("reverse_endianness", c_ushort)
    ]

class Globals(Structure):
    _fields_ = [
            ("exit", c_uint, 1),
            ("target", c_int), # pid_t
            ("matches", c_void_p), # matches_and_old_values_array*
            ("num_matches", c_ulong),
            ("scan_progress", c_double),
            ("stop_flag", c_bool),
            ("regions", c_void_p), # list_t*
            ("commands", c_void_p), #  list_t*
            ("current_cmdline", c_char_p),
            ("printversion", c_void_p), # void (*printversion)(FILE *outfd);
            ("options", GlobalOptions)
    ]

def get_global_vars():
        return Globals.in_dll(backend, "sm_globals")

def exec_command(strCmd):
    '''
        python strings are wchars, sm expects byte wide ascii.
        therefore, we've got to recreate the string
    '''
    strbuf = create_string_buffer(strCmd.encode('ascii'))
    return backend.sm_backend_exec_cmd(strbuf.raw)

def get_num_matches():
    return backend.sm_get_num_matches()

def get_version():
    return c_char_p(backend.sm_get_version()).value

def get_scan_progress():
    return backend.sm_get_scan_progress().value

def set_stop_flag(boolState):
    backend.sm_set_stop_flag(boolState)

@atexit.register
def unload():
    backend.sm_cleanup()

exec_command("version")

assert(get_num_matches() == 0)
assert(get_version() == b"0.17")
assert(get_scan_progress() == 0.0)

assert(get_global_vars().stop_flag == False)
set_stop_flag(True)
assert(get_global_vars().stop_flag == True)
