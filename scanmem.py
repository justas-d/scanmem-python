from ctypes import *
import ctypes.util
import atexit

libfile = ctypes.util.find_library("scanmem")

if libfile is None:
    raise OSError("Failed to find scanmem shared object.")

backend = CDLL(libfile)

backend.sm_init()
backend.sm_execcommand.argtypes = [POINTER(Globals), c_char_p]
backend.sm_execcommand.restype = c_bool
backend.sm_init.restype = c_bool

class Scanmem():

    def get_global_t(self):
        return Globals.in_dll(backend, "sm_globals")

    def exec_command(self, what):
        '''
            python strings are wchars, sm expects byte wide ascii.
            therefore, we've got to recreate the string
        '''
        strbuf = create_string_buffer(what.encode('ascii'))
        return backend.sm_execcommand(pointer(self.get_global_t()), strbuf.raw)

mem = Scanmem()
mem.exec_command("version")

@atexit.register
def unload():
    backend.sm_cleanup()
