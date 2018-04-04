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

c_pid_t = c_int
c_match_flags = c_uint16
c_wildcard_t = c_uint16
c_scan_match_type = c_uint32
c_list_t_ptr = c_void_p
c_region_scan_level_t = c_uint32
c_scan_data_type_t = c_uint32

''' 
    maps.h: region_scan_level_t
        determine which regions we need
'''
class RegionScanLevel():
    REGION_ALL = 0 # each of them 
    REGION_HEAP_STACK_EXECUTABLE = 1 # heap, stack, executable 
    REGION_HEAP_STACK_EXECUTABLE_BSS = 2 # heap, stack, executable, bss

'''
    value.h: match_flags
        match_flags: they MUST be implemented as an `uint16_t`, the `__packed__` ensures so.
        They are reinterpreted as a normal integer when scanning for VLT, which is
        valid for both endians, as the flags are ordered from smaller to bigger.
        NAMING: Primitive, single-bit flags are called `flag_*`, while aggregates,          
        defined for convenience, are called `flags_*`
'''
class MatchFlag():

    FLAGS_EMPTY = 0

    FLAG_U8B  = 1 << 0  # could be an unsigned  8-bit variable (e.g. unsigned char)      
    FLAG_S8B  = 1 << 1  # could be a    signed  8-bit variable (e.g. signed char)        
    FLAG_U16B = 1 << 2  # could be an unsigned 16-bit variable (e.g. unsigned short)     
    FLAG_S16B = 1 << 3  # could be a    signed 16-bit variable (e.g. short)              
    FLAG_U32B = 1 << 4  # could be an unsigned 32-bit variable (e.g. unsigned int)       
    FLAG_S32B = 1 << 5  # could be a    signed 32-bit variable (e.g. int)                
    FLAG_U64B = 1 << 6  # could be an unsigned 64-bit variable (e.g. unsigned long long) 
    FLAG_S64B = 1 << 7  # could be a    signed 64-bit variable (e.g. long long)          

    FLAG_F32B = 1 << 8  # could be a 32-bit floating point variable (i.e. float)         
    FLAG_F64B = 1 << 9  # could be a 64-bit floating point variable (i.e. double)        

    FLAGS_I8B  = FLAG_U8B  | FLAG_S8B
    FLAGS_I16B = FLAG_U16B | FLAG_S16B
    FLAGS_I32B = FLAG_U32B | FLAG_S32B
    FLAGS_I64B = FLAG_U64B | FLAG_S64B

    FLAGS_INTEGER = FLAGS_I8B | FLAGS_I16B | FLAGS_I32B | FLAGS_I64B
    FLAGS_FLOAT = FLAG_F32B | FLAG_F64B
    FLAGS_ALL = FLAGS_INTEGER | FLAGS_FLOAT

    FLAGS_8B   = FLAGS_I8B
    FLAGS_16B  = FLAGS_I16B
    FLAGS_32B  = FLAGS_I32B | FLAG_F32B
    FLAGS_64B  = FLAGS_I64B | FLAG_F64B

    FLAGS_MAX = 0XFFFF

'''
    value.h: mem64_t
        This union describes 8 bytes retrieved from target memory.
        Pointers to this union are the only ones that are allowed to be unaligned:                     
        to avoid performance degradation/crashes on arches that don't support unaligned access /* 
        (e.g. ARM) we access unaligned memory only through the attributes of this packed union. * 
        As described in http://www.alfonsobeato.net/arm/how-to-access-safely-unaligned-data/ ,  * 
        a packed structure forces the compiler to write general access methods to its members   * 
        that don't depend on alignment.                                                         * 
        So NEVER EVER dereference a mem64_t*, but use its accessors to obtain the needed type.  * 
'''
class Mem64(Union):
    _fields_ = [
        ("int8_value",              c_int8), 
        ("uint8_value",             c_uint8), 
        ("int16_value",             c_int16), 
        ("uint16_value",            c_uint16), 
        ("int32_value",             c_int32), 
        ("uint32_value",            c_uint32), 
        ("int64_value",             c_int64), 
        ("uint64_value",            c_uint64), 
        ("float32_value",           c_float), 
        ("float64_value",           c_double), 
        ("bytes[sizeof(int64_t)]",  c_uint8 * sizeof(c_int64)),
        ("chars[sizeof(int64_t)]",  c_char * sizeof(c_int64))   
    ]

'''
    value.h: wildcard_t
        bytearray wildcards: they must be uint8_t. They are ANDed with the incoming
        memory before the comparison, so that '??' wildcards always return true
        It's possible to extend them to fully granular wildcard-ing, if needed
'''
class ValueWildcard():
    FIXED = 0xff
    WILDCARD = 0x00

'''
    value.h: uservalue_t
        this struct describes values provided by users
'''
class UserValue(Structure):
    _fields_ = [
        ("int8_value",      c_int8),
        ("uint8_value",     c_uint8),
        ("int16_value",     c_int16),
        ("uint16_value",    c_uint16),
        ("int32_value",     c_int32),
        ("uint32_value",    c_uint32),
        ("int64_value",     c_int64),
        ("uint64_value",    c_uint64),
        ("float32_value",   c_float),    
        ("float64_value",   c_double),
        ("bytearray_value", POINTER(c_uint8)),
        ("wildcard_value",  POINTER(c_wildcard_t)),
        ("string_value",    c_char_p),
        ("match_flags",     c_match_flags)
    ]

''' 
    value.h: value_t 
        this struct describes matched values
'''
class SetValue(Structure):

    class SetValueUnion(Union):
        _fields_ = [
            ("int8_value",              c_int8), 
            ("uint8_value",             c_uint8), 
            ("int16_value",             c_int16), 
            ("uint16_value",            c_uint16), 
            ("int32_value",             c_int32), 
            ("uint32_value",            c_uint32), 
            ("int64_value",             c_int64), 
            ("uint64_value",            c_uint64), 
            ("float32_value",           c_float), 
            ("float64_value",           c_double), 
            ("bytes[sizeof(int64_t)]",  c_uint8 * sizeof(c_int64)),
            ("chars[sizeof(int64_t)]",  c_char * sizeof(c_int64))
    ]

    _fields_ = [
        ("value", SetValueUnion),
        ("flags", c_match_flags)
    ]


''' scanroutines.h: scan_data_type_t '''
class ScanDataType():
    ANYNUMBER = 0 # ANYINTEGER or ANYFLOAT
    ANYINTEGER = 1 # INTEGER of whatever width
    ANYFLOAT = 2 # FLOAT of whatever width
    INTEGER8 = 3
    INTEGER16 = 4
    INTEGER32 = 5
    INTEGER64 = 6
    FLOAT32 = 7
    FLOAT64 = 8
    BYTEARRAY = 9
    STRING = 10


''' scanroutines.h: scan_match_type_t '''
class ScanMatchType():
    MATCH_ANY = 0                # for snapshot
    # following: compare with a given value
    MATCH_EQUAL_TO = 1
    MATCH_NOTEQUAL_TO = 2
    MATCH_GREATER_THAN = 3
    MATCH_LESS_THAN = 4
    MATCH_RANGE = 5
    # following: compare with the old value
    MATCH_UPDATE = 6
    MATCH_NOT_CHANGED = 7
    MATCH_CHANGED = 8
    MATCH_INCREASED = 9
    MATCH_DECREASED = 10
    # following: compare with both given value and old value
    MATCH_INCREASED_BY = 11
    MATCH_DECREASED_BY = 12

''' scanmem.h: globals_t::options '''
class GlobalOptions(Structure):
    _fields_ = [
            ("alignment",           c_uint16),
            ("debug",               c_uint16),
            ("backend",             c_uint16),
            ("scan_data_type",      c_scan_data_type_t), 
            ("region_scan_level",   c_region_scan_level_t),
            ("dump_with_ascii",     c_uint16),
            ("reverse_endianness",  c_uint16)
    ]

''' scanmem.h: globals_t '''
class Globals(Structure):
    _fields_ = [
            ("exit",            c_uint32, 1),
            ("target",          c_pid_t),
            ("matches",         c_void_p), # matches_and_old_values_array*
            ("num_matches",     c_uint64),
            ("scan_progress",   c_double),
            ("stop_flag",       c_bool),
            ("regions",         c_list_t_ptr),
            ("commands",        c_list_t_ptr), 
            ("current_cmdline", c_char_p),
            ("printversion",    c_void_p), # void (*printversion)(FILE *outfd);
            ("options",         GlobalOptions)
    ]

backend.sm_init_ctx.argtypes            = [POINTER(Globals)]
backend.sm_cleanup_ctx.argtypes         = [POINTER(Globals)]
backend.sm_set_backend_ctx.argtypes     = [POINTER(Globals)]
backend.sm_get_num_matches.argtypes     = [POINTER(Globals)]
backend.sm_get_scan_progress.argtypes      = [POINTER(Globals)]
backend.sm_backend_exec_cmd_ctx.argtypes= [POINTER(Globals), c_char_p]
backend.sm_set_stop_flag.argtypes       = [POINTER(Globals), c_bool]
backend.sm_detach.argtypes              = [c_pid_t]
backend.sm_setaddr.argtypes             = [c_pid_t, c_void_p, POINTER(SetValue)]
backend.sm_checkmatches.argtypes        = [POINTER(Globals), c_scan_match_type, POINTER(UserValue)]
backend.sm_searchregions.argtypes       = [POINTER(Globals), c_scan_match_type, POINTER(UserValue)]
backend.sm_peekdata.argtypes            = [c_void_p, c_uint16, POINTER(POINTER(Mem64)), c_size_t]
backend.sm_attach.argtypes              = [c_pid_t]
backend.sm_read_array.argtypes          = [c_pid_t, c_void_p, c_void_p, c_size_t]
backend.sm_write_array.argtypes         = [c_pid_t, c_void_p, c_void_p, c_size_t]
backend.sm_readmaps.argtypes            = [c_pid_t, c_list_t_ptr, c_region_scan_level_t]
backend.sm_reset.argtypes               = [POINTER(Globals)]

backend.sm_init_ctx.restype             = c_bool
backend.sm_backend_exec_cmd_ctx.restype = c_bool
backend.sm_get_num_matches.restype      = c_ulong
backend.sm_get_version.restype          = c_char_p
backend.sm_get_scan_progress.restype    = c_double
backend.sm_detach.restype               = c_bool 
backend.sm_setaddr.restype              = c_bool 
backend.sm_checkmatches.restype         = c_bool 
backend.sm_searchregions.restype        = c_bool 
backend.sm_peekdata.restype             = c_bool 
backend.sm_attach.restype               = c_bool 
backend.sm_read_array.restype           = c_bool 
backend.sm_write_array.restype          = c_bool 
backend.sm_readmaps.restype             = c_bool
backend.sm_reset.restype                = c_bool


class Scanmem():
    def __init__(self):
        self.globals = Globals()
        self.globals_ptr = pointer(self.globals)
        self.are_commands_initialized = False

    def __del__(self):
        if self.are_commands_initialized:
            self.cleanup()

    def get_global_vars(self):
            return Globals.in_dll(backend, "sm_globals")

    ''' commands.h '''
    ''' bool sm_backend_exec_cmd_ctx(globals_t *vars, const char *commandline); '''
    def exec_command(self, strCmd):
        '''
            python strings are wchars, sm expects byte wide ascii.
            therefore, we've got to recreate the string
        '''
        backend.sm_execcommand(self.globals_ptr, strCmd.encode('ascii'))

    ''' scanmem.h '''
    ''' bool sm_init_ctx(globals_t *vars); '''
    def init(self):
        if self.are_commands_initialized: return false
        return backend.sm_init_ctx(self.globals_ptr)

    ''' void sm_cleanup_ctx(globals_t *vars); '''
    def cleanup(self):
        if not self.are_commands_initialized: return false
        return backend.sm_cleanup_ctx(self.globals_ptr)

    ''' unsigned long sm_get_num_matches_ctx(globals_t *vars); '''
    def get_num_matches(self):
        return backend.sm_get_num_matches_ctx(self.globals_ptr)

    ''' const char *sm_get_version(void); '''
    def get_version(self):
        return c_char_p(backend.sm_get_version()).value

    ''' double sm_get_scan_progress_ctx(globals_t *vars); '''
    def get_scan_progress(self):
        return backend.sm_get_scan_progress_ctx(self.globals_ptr)

    ''' void sm_set_stop_flag_ctx(globals_t *vars, bool stop_flag); '''
    def set_stop_flag(self, boolState):
        backend.sm_set_stop_flag_ctx(self.globals_ptr, boolState)

    ''' void sm_set_backend_ctx(globals_t *vars); '''
    def set_backend(self):
        backend.sm_set_backend_ctx(self.globals_ptr)

# TODO ptrace.c
# bool sm_detach(pid_t target);
    def detach(self, pidTarget):
        return backend.sm_detach(pidTarget)

# bool sm_setaddr(pid_t target, void *addr, const value_t *to);
    def set_address(self, pidTarget, ptrAddress, userValue):
        return backend.sm_setaddr(pidTarget, ptrAddress, pointer(userValue))

    def set_address_ptr(self, pidTarget, ptrAddress, ptrUserValue):
        return backend.sm_setaddr(pidTarget, ptrAddress, ptrUserValue)

# bool sm_checkmatches(globals_t *vars, scan_match_type_t match_type, const uservalue_t *uservalue);
    def check_matches(self, matchType, userValue):
        return backend.sm_checkmatches(self.globals_ptr, matchType, pointer(userValue))

    def check_matches_ptr(self, matchType, ptrUserValue):
        return backend.sm_checkmatches(self.globals_ptr, matchType, ptrUserValue)

# bool sm_searchregions(globals_t *vars, scan_match_type_t match_type, const uservalue_t *uservalue);
    def search_regions(self, matchType, userValue):
        return backend.sm_searchregions(self.globals_ptr, matchType, pointer(userValue))

    def search_regions_ptr(self, matchType, ptrUserValue):
        return backend.sm_searchregions(self.globals_ptr, matchType, ptrUserValue)

# bool sm_peekdata(const void *addr, uint16_t length, const mem64_t **result_ptr, size_t *memlength);
    def peek_data(self, ptrAddress, length, ptrResultArray, ptrMemLength):
        return backend.sm_peekdata(ptrAddress, length, ptrResultArray, ptrMemLength)

# bool sm_attach(pid_t target);
    def attach(self, pidTarget):
        return backend.sm_attach(pidTarget)

# bool sm_read_array(pid_t target, const void *addr, void *buf, size_t len);
    def read_array(self, pidTarget, ptrAddress, ptrBuffer, length):
        return backend.sm_read_array(pidTarget, ptrAddress, ptrBuffer, length)

# bool sm_write_array(pid_t target, void *addr, const void *data, size_t len);
    def write_array(self, pidTarget, ptrAddress, ptrData, length):
        return backend.sm_read_array(pidTarget, ptrAddress, ptrData, length)

# bool sm_readmaps(pid_t target, list_t *regions, region_scan_level_t region_scan_level);
    def read_maps(self):
        return backend.sm_readmaps(self.globals.target, self.globals.regions, self.globals.options.region_scan_level)

# bool sm_reset(globals_t* vars);
    def reset(self):
        return backend.sm_reset(self.globals_ptr)

pid = 5526

scanmem = Scanmem()
scanmem.globals.target = pid

val = UserValue()
val.match_flags = MatchFlag.FLAGS_INTEGER
val.uint16_value = int(input())

scanmem.reset()
scanmem.read_maps()
scanmem.search_regions(ScanMatchType.MATCH_EQUAL_TO, val)
