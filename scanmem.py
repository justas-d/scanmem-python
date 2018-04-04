from ctypes import *
import ctypes.util
import atexit

libfile = ctypes.util.find_library("scanmem")

if libfile is None:
    raise OSError("Failed to find scanmem shared object.")

backend = CDLL(libfile)

class OldValueAndMatchInfo(Structure):
    _fields_ = [
            ("old_value", c_ushort),
            ("match_info", c_short) # originally match_flags but is stored as an u16 according to value.h
    ]

class MatchesAndOldValuesSWATH(Structure):
    _pack_ = 4 # aligned(sizeof(old_value_and_match_info)))
    _fields_ = [
            ("first_byte_in_child", c_void_p),
            ("max_needed_bytes", c_size_t),
            ("data", OldValueAndMatchInfo * 0)

    ]
'''
typedef struct element {
    void *data;
    struct element *next;
} element_t;

typedef struct {
    size_t size;
    element_t *head;
    element_t *tail;
} list_t;
'''

class MatchesAndOldValuesArray(Structure):
    _fields_ = [
            ("bytes_allocated", c_size_t),
            ("max_needed_bytes", c_size_t),
            ("swaths", MatchesAndOldValuesSWATH * 0)
    ]

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
            ("matches", POINTER(MatchesAndOldValuesArray)),
            ("num_matches", c_ulong),
            ("scan_progress", c_double),
            ("stop_flag", c_bool),
            ("regions", c_void_p), # TODO: list_t*
            ("commands", c_void_p), # TODO: list_t*
            ("current_cmdline", c_char_p),
            ("printversion", c_void_p), # TODO void (*printversion)(FILE *outfd);
            ("options", GlobalOptions)
    ]

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
