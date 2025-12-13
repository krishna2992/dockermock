import os
import ctypes 
import socket
from .libc_ import *
from .headers import *



def get_interface_names():
    if not hasattr(get_interface_names, 'inited'):
        # Set argtypes and restype for getifaddrs and freeifaddrs
        libc.getifaddrs.argtypes = [ctypes.POINTER(ctypes.POINTER(ifaddrs))]
        libc.getifaddrs.restype = ctypes.c_int
        libc.freeifaddrs.argtypes = [ctypes.POINTER(ifaddrs)]
        libc.freeifaddrs.restype = None
        get_interface_names.inited = True
        
    ifap = ctypes.POINTER(ifaddrs)()
    if libc.getifaddrs(ctypes.byref(ifap)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
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


def get_if_index(interface: str, sock=None):
    ifr = Ifreq()
    ifr.ifr_name = interface.encode("utf-8")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if not sock else sock
    res = libc.ioctl(s.fileno(), SIOCGIFINDEX, ctypes.byref(ifr))
    s.close() if not sock else None
    if res != 0:
        return -1
    
    return ifr.ifr_ifru.ifru_index



def get_interface_groups(interface: str, sock=None):
    MAX_GROUPS = 8
    group_array_type = ifg_req * MAX_GROUPS
    group_array = group_array_type()
    ifgr = ifgroupreq()
    ifgr.ifgr_name = interface.encode('utf-8').ljust(IFNAMSIZ, b'\x00')
    ifgr.ifgr_len = ctypes.sizeof(group_array)
    ifgr.ifgr_ifgru.ifgru_groups = ctypes.cast(group_array, ctypes.POINTER(ifg_req))    

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if not sock else sock
    res = libc.ioctl(s.fileno(), SIOCGIFGROUP, ctypes.byref(ifgr))
    s.close() if not sock else None
    if res != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))

    group_count = ifgr.ifgr_len // ctypes.sizeof(ifg_req)
    return [group_array[i].ifgrq_ifgrqu.ifgrqu_group.decode('utf-8').rstrip('\x00') for i in range(group_count) if group_array[i].ifgrq_ifgrqu.ifgrqu_group]

def  set_interface_group(interface: str, group_name:str, sock=None):
    if not interface:
        print('Interface should not be null')
        return -1
    if not group_name:
        print('group_name should not be null')
        return -1
    ifgr = ifgroupreq()
    ifgr.ifgr_name = interface.encode('utf-8').ljust(IFNAMSIZ, b'\x00')
    ifgr.ifgr_ifgru.ifgru_group = group_name.encode('utf-8').ljust(IFNAMSIZ, b'\x00')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if not sock else sock
    res = libc.ioctl(s.fileno(), SIOCAIFGROUP, ctypes.byref(ifgr))
    s.close() if not sock else None
    if res != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def create_interface(base_name="epair", sock=None):
    ifr = Ifreq()
    ifr.ifr_name = base_name.encode("utf-8")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if not sock else sock
    ret = libc.ioctl(s.fileno(), SIOCIFCREATE2, ctypes.byref(ifr))
    s.close() if not sock else None
    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"ioctl SIOCIFCREATE2 failed: {os.strerror(errno)}")

    name = ifr.ifr_name.decode("utf-8").rstrip("\x00")
    return name

def destroy_interface(name, sock=None):
    ifr = Ifreq()
    ifr.ifr_name = name.encode("utf-8")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if not sock else sock
    ret = libc.ioctl(s.fileno(), SIOCIFDESTROY, ctypes.byref(ifr))
    s.close() if not sock else None

    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"ioctl SIOCIFDESTROY failed: {os.strerror(errno)}")
    

def rename_interface(name, newname, sock=None):
    ifr = Ifreq()
    ifr.ifr_name = name.encode("utf-8")
    
    ifr.ifr_ifru.ifru_data = ctypes.cast(
        ctypes.create_string_buffer(
            newname.encode('utf-8')
        ), 
        ctypes.c_void_p
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if not sock else sock
    ret = libc.ioctl(s.fileno(), SIOCSIFNAME, ctypes.byref(ifr))
    s.close() if not sock else None

    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"ioctl SIOCSIFNAME failed: {os.strerror(errno)}")

def move_to_jail(name, jid, sock=None):
    ifr = Ifreq()
    ifr.ifr_name = name.encode("utf-8")
    ifr.ifr_ifru.ifru_jid = jid

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if not sock else sock
    ret = libc.ioctl(s.fileno(), SIOCSIFVNET, ctypes.byref(ifr))
    s.close() if not sock else None

    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"ioctl SIOCSIFVNET failed: {os.strerror(errno)}")


def remove_from_jail(name, jid, sock=None):
    ifr = Ifreq()
    ifr.ifr_name = name.encode("utf-8")
    ifr.ifr_ifru.ifru_jid = jid

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if not sock else sock
    ret = libc.ioctl(s.fileno(), SIOCSIFRVNET, ctypes.byref(ifr))
    s.close() if not sock else None

    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"ioctl SIOCSIFVNET failed: {os.strerror(errno)}")
    

def bridge_if(bridge_if_name, member_if, add=True, sock=None):
    ifd = Ifdrv()
    req = Ifbreq()
    req.ifbr_ifsname = member_if.encode('utf-8').ljust(IFNAMSIZ, b'\x00')

    ifd.ifd_name = bridge_if_name.encode('utf-8').ljust(IFNAMSIZ, b'\x00')
    ifd.ifd_cmd = BRDGADD if add else BRDGDEL
    ifd.ifd_len = ctypes.sizeof(req);
    ifd.ifd_data = ctypes.cast(ctypes.pointer(req), ctypes.c_void_p)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if not sock else sock
    res = libc.ioctl(s.fileno(), SIOCSDRVSPEC, ctypes.byref(ifd))

    if res != 0:
        s.close() if not sock else None
        errno = ctypes.get_errno()
        raise OSError(errno, f"ioctl SIOCSDRVSPEC failed: {os.strerror(errno)}")
    
    try:
        set_if_flag(member_if, IFF_UP, sock=s)
        s.close() if not sock else None
    except OSError as e:
        s.close() if not sock else None
        raise e


def set_ip_address(ifname, ip_addr, net_mask, broadcast_addr=None, sock=None):
    ifra = IfAliasReq()
    
    ifra.ifra_name=ifname.encode('utf-8').ljust(IFNAMSIZ, b'\x00')
    def set_addr(sock_addr, addr_str):
        sin_ptr = ctypes.cast(ctypes.pointer(sock_addr), ctypes.POINTER(SockaddrIn))
        sin = sin_ptr.contents
        sin.sin_family = socket.AF_INET
        sin.sin_len = ctypes.sizeof(SockaddrIn)
        packed_ip = socket.inet_pton(socket.AF_INET, addr_str)  # returns 4 bytes
        ctypes.memmove(ctypes.byref(sin.sin_addr), packed_ip, 4) 
    # Do for IP Addr
    set_addr(ifra.ifra_addr, ip_addr)
    # Do for Netmask
    set_addr(ifra.ifra_mask, net_mask)
    # Do for broadcast_addr
    if broadcast_addr:
        set_addr(ifra.ifra_broadaddr, broadcast_addr)
    # Call IOCTL
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if not sock else sock
    res = libc.ioctl(s.fileno(), SIOCAIFADDR, ctypes.byref(ifra))

    if res != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"ioctl SIOCAIFADDR failed: {os.strerror(errno)}")
    try:
        set_if_flag(ifname, IFF_UP, sock=s)
        s.close() if not sock else None
    except OSError as e:
        s.close() if not sock else None
        raise e
    

def get_if_flags(name, sock=None):
    ifr = Ifreq()
    ifr.ifr_name = name.encode("utf-8").ljust(IFNAMSIZ, b'\x00')

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if not sock else sock
    res = libc.ioctl(s.fileno(), SIOCGIFFLAGS, ctypes.byref(ifr))
    s.close() if not sock else None

    if res < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"ioctl SIOCGIFFLAGS failed: {os.strerror(errno)}")
    arr = ifr.ifr_ifru.ifru_flags    
    flags = (arr[0] & 0xFFFF) | (arr[1] << 16)
    return flags


def set_if_flag(name, flag, sock=None):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if not sock else sock
    flags = get_if_flags(name, sock=s)
    flags |= flag
    ifr = Ifreq()
    ifr.ifr_name = name.encode("utf-8").ljust(IFNAMSIZ, b'\x00')
    ifr.ifr_ifru.ifru_flags[0] = flags & 0xFFFF
    ifr.ifr_ifru.ifru_flags[1] = (flags >> 16) & 0xFFFF
    
    res = libc.ioctl(s.fileno(), SIOCSIFFLAGS, ctypes.byref(ifr))
    s.close() if not sock else None

    if res < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"ioctl SIOCSIFFLAGS failed: {os.strerror(errno)}")
    
def clear_if_flag(name, flag, sock=True):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) if not sock else sock
    flags = get_if_flags(name, sock=s)
    flags &= ~flag
    ifr = Ifreq()
    ifr.ifr_name = name.encode("utf-8").ljust(IFNAMSIZ, b'\x00')

    ifr.ifr_ifru.ifru_flags[0] = flags & 0xFFFF
    ifr.ifr_ifru.ifru_flags[1] = (flags >> 16) & 0xFFFF

    res = libc.ioctl(s.fileno(), SIOCSIFFLAGS, ctypes.byref(ifr))
    s.close() if not sock else None
    
    if res < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"ioctl SIOCSIFFLAGS failed: {os.strerror(errno)}")
    