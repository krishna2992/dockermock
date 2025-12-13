from ctypes.util import find_library
import ctypes 
libc = ctypes.CDLL(find_library("c"), use_errno=True)
