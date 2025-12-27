import ctypes
import os, sys
print(sys.path.append('/home/krishna/Projects/dockermock'))
from app2.wrappers import libc, Iovec, int_iovec, str_iovec


libc.nmount.argtypes = [ctypes.POINTER(Iovec), ctypes.c_uint, ctypes.c_int]
libc.nmount.restype = ctypes.c_int

flags = 0
below = 1
from_path = "/home/krishna/Projects/Garbage/BASE"
fspath = "/home/krishna/Projects/Garbage/UPPER"

iovecs = []
iovecs.extend(str_iovec("fstype", "unionfs"))
iovecs.extend(str_iovec("fspath", fspath))
iovecs.extend(str_iovec("from", from_path))
iovecs.extend(int_iovec("below", 1))
iovecs.extend(int_iovec("noatime", 1))
iovecs.extend(str_iovec("copymode", "traditional"))
iovecs.extend(int_iovec("readonly", 1))
iov_array = (Iovec * len(iovecs))(*iovecs)
res =  libc.nmount(iov_array, len(iov_array), flags)
if res<0:
    print(res,':', os.strerror(res))


from_path = "/home/krishna/Projects/Garbage/UPPER"
fspath = "/home/krishna/Projects/Garbage/THIRD"


iovecs = []
iovecs.extend(str_iovec("fstype", "unionfs"))
iovecs.extend(str_iovec("fspath", fspath))
iovecs.extend(str_iovec("from", from_path))
iovecs.extend(int_iovec("below", 1))
iovecs.extend(int_iovec("noatime", 1))
iovecs.extend(str_iovec("copymode", "transparent"))
iovecs.extend(str_iovec("whiteout", "whenneeded"))

# iovecs.extend(int_iovec("readonly", 1))
iov_array = (Iovec * len(iovecs))(*iovecs)
res =  libc.nmount(iov_array, len(iov_array), flags)
if res<0:
    print(res,':', os.strerror(ctypes.get_errno()))