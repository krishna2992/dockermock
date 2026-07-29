from ctypes.util import find_library
import os
import ctypes 
import logging

logger = logging.getLogger(__name__)

libc_path = find_library("c")
libc = ctypes.CDLL(libc_path, use_errno=True)
########################################################################

JAIL_CREATE	= 0x01	
JAIL_UPDATE	= 0x02
JAIL_ATTACH	= 0x04	


######################### Structures ###################################
class Iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t)
    ]

class InAddr(ctypes.Structure):
    _fields_ = [("s_addr", ctypes.c_uint32)]


class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort),
                ("sa_data", ctypes.c_char * 14)]


class ifaddrs(ctypes.Structure):
    pass

ifaddrs._fields_ = [
    ("ifa_next", ctypes.POINTER(ifaddrs)),
    ("ifa_name", ctypes.c_char_p),
    ("ifa_flags", ctypes.c_uint),
    ("ifa_addr", ctypes.POINTER(sockaddr)),
    ("ifa_netmask", ctypes.POINTER(sockaddr)),
    ("ifa_dstaddr", ctypes.POINTER(sockaddr)),
    ("ifa_data", ctypes.c_void_p)
]



########################### IOVECS ######################################
def str_iovec(key: str, value: str) -> [Iovec, Iovec]:
    """Create a pair of iovecs for jail_get key/value."""
    key_bytes = key.encode("utf-8") + b"\x00"
    val_bytes = value.encode("utf-8") + b"\x00"
    return [
        Iovec(ctypes.cast(ctypes.create_string_buffer(key_bytes), ctypes.c_void_p), len(key_bytes)),
        Iovec(ctypes.cast(ctypes.create_string_buffer(val_bytes), ctypes.c_void_p), len(val_bytes)),
    ]



def addr_iovec(ips):
    key_bytes = "ip4.addr".encode("utf-8") + b"\x00"
    libc.inet_aton.argtypes = [ctypes.c_char_p, ctypes.POINTER(InAddr)]
    libc.inet_aton.restype = ctypes.c_int
    in_addrs = []
    # Example usage
    for ip in ips:
        addr = InAddr()
        result = libc.inet_aton(ip.encode('utf-8'), ctypes.byref(addr))
        if result != 0:
            print(f"IP converted: {hex(addr.s_addr)}")  # Typically: 0x0100007f (little-endian)
            in_addrs.append(addr)
        else:
            print("Invalid IP address")

    inaddr_arr = (InAddr * len(in_addrs))(*in_addrs)
    print(inaddr_arr)
    return [
        Iovec(ctypes.cast(ctypes.create_string_buffer(key_bytes), ctypes.c_void_p), len(key_bytes)),
        Iovec(ctypes.cast(inaddr_arr, ctypes.c_void_p), ctypes.sizeof(InAddr())*len(in_addrs))
    ]
    
def int_iovec(key: str, value: int) -> [Iovec, Iovec]:
    """Create a pair of iovecs for jail_get key/value."""
    key_bytes = key.encode("utf-8") + b"\x00"
    cval = ctypes.c_int(value)
    cval_ptr = ctypes.pointer(cval)
    return [
        Iovec(ctypes.cast(ctypes.create_string_buffer(key_bytes), ctypes.c_void_p), len(key_bytes)),
        Iovec(ctypes.cast(cval_ptr, ctypes.c_void_p), ctypes.sizeof(cval))
    ]

def empty_iovec(key: str) -> [Iovec, Iovec]:
    key_bytes = key.encode("utf-8") + b"\x00"
    null_ptr = ctypes.c_void_p(None)
    return [
        Iovec(ctypes.cast(ctypes.create_string_buffer(key_bytes), ctypes.c_void_p), len(key_bytes)),
        Iovec(null_ptr, 0)
    ]

def errmsg_iovec():
    key = b"errmsg\x00"
    buf = ctypes.create_string_buffer(256)
    return [
        Iovec(ctypes.cast(ctypes.create_string_buffer(key), ctypes.c_void_p), len(key)),
        Iovec(ctypes.cast(buf, ctypes.c_void_p), ctypes.sizeof(buf))
    ], buf


############################Wrapper Functions#################################


def setup_get_ifname_wrapper():
    libc.getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(ifaddrs))]
    libc.getifaddrs.restype = ctypes.c_int
    libc.freeifaddrs.argtypes = [ctypes.POINTER(ifaddrs)]
    libc.freeifaddrs.restype = None

def setup_set_proc_title():
    libc.setproctitle.argtypes = [ctypes.c_char_p]
    libc.setproctitle.restype = None

def set_proc_title_wrapper(title: str) -> None:
    """Set process title using FreeBSD libc setproctitle."""
    fmt = title.encode('utf-8')
    libc.setproctitle(fmt)


def get_interface_names_wrapper():
    ifap = ctypes.POINTER(ifaddrs)()
    if libc.getifaddrs(ctypes.byref(ifap)) != 0:
        raise OSError(100, "getifaddrs failed")
    names = set()
    try:
        p = ifap
        while p:
            name = p.contents.ifa_name.decode()
            names.add(name)
            p = p.contents.ifa_next
    finally:
        libc.freeifaddrs(ifap)
    return sorted(names)


def jail_set_wrapper(iovs, flags) -> int:
    iov_array = (Iovec*len(iovs))(*iovs)
    libc.jail_set.argtypes = [ctypes.POINTER(Iovec), ctypes.c_uint, ctypes.c_int]
    libc.jail_set.restype = ctypes.c_int
    return libc.jail_set(iov_array, len(iov_array), flags)
    

def jail_remove_wrapper(jid: int):
    libc.jail_remove.argtypes = [ctypes.c_int]
    libc.jail_remove.restype = ctypes.c_int
    result = libc.jail_remove(jid)
    return result

def jail_attach_wrapper(jid: int):
    libc.jail_attach.argtypes = [ctypes.c_int]
    libc.jail_attach.restype = ctypes.c_int
    result = libc.jail_attach(jid)
    return result
    

def get_jail_id_by_name(name: str) -> int:
    """Use jail_get to retrieve jail ID by name."""
    iovecs = str_iovec("name", name)
    iov_array = (Iovec * len(iovecs))(*iovecs)
    libc.jail_get.argtypes = [ctypes.POINTER(Iovec), ctypes.c_uint, ctypes.c_int]
    libc.jail_get.restype = ctypes.c_int
    jid = libc.jail_get(iov_array, len(iovecs), 0)
    return jid

def rfork_wrapper(flags: int):
    libc.rfork.argtypes = [ctypes.c_int]
    libc.rfork.restype = ctypes.c_int
    cflags = ctypes.c_int(flags)
    return libc.rfork(cflags)


def mount_devfs(path:str, ruleset:int=4, flags=0):
    iovecs = []
    iovecs.extend(str_iovec("fstype", "devfs"))
    iovecs.extend(str_iovec("fspath", path))
    iovecs.extend(str_iovec("ruleset", str(ruleset)))
    iov_array = (Iovec * len(iovecs))(*iovecs)
    libc.nmount.argtypes = [ctypes.POINTER(Iovec), ctypes.c_uint, ctypes.c_int]
    libc.nmount.restype = ctypes.c_int
    return libc.nmount(iov_array, len(iov_array), flags)

def mount_fdescfs(path:str, ruleset:int=4, flags=0):
    iovecs = []
    iovecs.extend(str_iovec("fstype", "fdescfs"))
    iovecs.extend(str_iovec("fspath", path))
    iov_array = (Iovec * len(iovecs))(*iovecs)
    libc.nmount.argtypes = [ctypes.POINTER(Iovec), ctypes.c_uint, ctypes.c_int]
    libc.nmount.restype = ctypes.c_int
    return libc.nmount(iov_array, len(iov_array), flags)

def mount_tmpfs(path:str, flags=0):
    iovecs = []
    iovecs.extend(str_iovec("fstype", "tmpfs"))
    iovecs.extend(str_iovec("fspath", path))
    iov_array = (Iovec * len(iovecs))(*iovecs)
    libc.nmount.argtypes = [ctypes.POINTER(Iovec), ctypes.c_uint, ctypes.c_int]
    libc.nmount.restype = ctypes.c_int
    return libc.nmount(iov_array, len(iov_array), flags)


def mount_nullfs(path:str, from_path:str, flags=0):
    iovecs = []
    iovecs.extend(str_iovec("fstype", "nullfs"))
    iovecs.extend(str_iovec("fspath", path))
    iovecs.extend(str_iovec("from", from_path))
    iov_array = (Iovec * len(iovecs))(*iovecs)
    libc.nmount.argtypes = [ctypes.POINTER(Iovec), ctypes.c_uint, ctypes.c_int]
    libc.nmount.restype = ctypes.c_int
    return libc.nmount(iov_array, len(iov_array), flags)

def mount_unionfs(image_root, container_root, flags=0):
    iovecs = []
    iovecs.extend(str_iovec("fstype", "unionfs"))
    iovecs.extend(str_iovec("fspath", container_root))
    iovecs.extend(str_iovec("from", image_root))
    iovecs.extend(int_iovec("below", 1))
    iovecs.extend(int_iovec("noatime", 1))
    iovecs.extend(str_iovec("copymode", "transparent"))
    iovecs.extend(str_iovec("whiteout", "whenneeded"))
    iov_array = (Iovec * len(iovecs))(*iovecs)
    return  libc.nmount(iov_array, len(iov_array), flags)
    
def unmount(path):
    logger.debug(f"Unmouting: {path}")
    res = libc.unmount(path.encode('utf-8'), 0)
    if res != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
#############################################################################
# def main():
#     iovs = []
#     iovs.extend(str_iovec("name", "myjail"))
#     iovs.extend(str_iovec("path", "/jails/templates/14.1-RELEASE"))
#     iovs.extend(str_iovec("host.hostname", "testjail.local"))
#     iovs.extend(int_iovec("devfs_ruleset", 4))
#     iovs.extend(empty_iovec("allow.raw_sockets"))
#     iovs.extend(int_iovec("allow.mount", 1))
#     iovs.extend(int_iovec("allow.mount.devfs", 1))
#     iovs.extend(int_iovec("ip4", 1))
#     iovs.extend(empty_iovec("persist"))
#     err_iov, buf = errmsg_iovec()
#     iovs.extend(err_iov)
#     iovs.extend(addr_iovec(["192.168.1.100"]))
#     iovec_array = (Iovec*len(iovs))(*iovs)
#     jid = jail_set_wrapper(iovs)
#     if jid < 0:
#         errno = ctypes.get_errno()
#         print("Detailed error:", buf.value.decode())
#         print(f"jail_set failed : {os.strerror(errno)}")
#     print(f"Jail created with {jid}")
    

# main()