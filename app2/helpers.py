import json, sys
import re
import subprocess
from pathlib import Path
from .lib import *
from .wrappers import *
import collections

CENOERR   = 0
CERROR    = -1
CENOJAIL  = -1
CENOPATH  = -3
CEINVALD  = -4
CEATTERR  = -5
CEMNTPOT  = -6
CEMNTDEV  = -7
CEUMNTERR = -8

class JailDoesNotExist(Exception):
    def __init__(self, jail_name, jail_id=None, *args, **kwargs):
        msg = f"Unable to find jail: {jail_name or jail_id!s}"
        super().__init__(msg, *args, **kwargs)

class CustomException(Exception):
    def __init__(self, err_msg, jail_name, jail_id=None, *args, **kwargs):
        msg = f"Jail {jail_name or jail_id!s}: {err_msg}"
        super().__init__(msg, *args, **kwargs)




def json_to_iovec(data):
    iovecs = []
    for key, value in data.items():
        if key == 'ip4.addr':
            if isinstance(value, str):
                iovecs.extend(addr_iovec([value]))
            elif isinstance(value, collections.abc.Iterable):
                iovecs.extend(addr_iovec(value))
        if isinstance(value, str):
            iovecs.extend(str_iovec(key, value))
        elif isinstance(value, int):
            iovecs.extend(int_iovec(key, value))
        elif isinstance(value, bool):
            if value == False:
                iovecs.extend(empty_iovec('no'+key))
            else:
                iovecs.extend(empty_iovec(key))
    err_iov, buf = errmsg_iovec()
    iovecs.extend(err_iov)
    return iovecs, buf

def jail_get_id(name:str):
    if not name:
        return -1
    return get_jail_id_by_name(name)


def start_jail_from_json(data):
    iovec, buf = json_to_iovec(data) 
    jid = jail_set_wrapper(iovec, JAIL_CREATE)
    if jid<0:
        print(buf.value)
    return jid

def check_interface_exist(name:str):
    if not name:
        return -1
    return get_if_index(name)!= -1

def create_bridge(name:str=None):
    isvalid_bridge = lambda  x: bol(re.fullmatch(r"bridge(\d+)?", x))
    bridge_name = "bridge"
    if name and isvalid_bridge(name):
        bridge_name =  name
    try:
        return create_interface(bridge_name)
    except OSError as e:
        print("Error:", e.strerror, file=sys.stderr)
        return None


def create_epair(name:str|None=None, sock=None):
    isvalid_epair = lambda  x: bol(re.fullmatch(r"epair(\d+)?", x))
    epair_name = "epair"
    if name and isvalid_epair(name):
        epair_name =  name
    try:
        return create_interface(epair_name, sock)
    except OSError as e:
        print("Error:", e.strerror, file=sys.stderr)
        return None

def destroy_if(name):
    if not name:
        return CEINVALD
    try:
        print("Destrying interface: ", name)
        destroy_interface(name)
        return CENOERR
    except OSError as e:
        print("Error:", e.strerror, file=sys.stderr)
        return CERROR


def attach_vnet_ifaces(j_name, if_name):
    jid = get_jail_id_by_name(j_name)
    if jid<0:
        return CENOJAIL
    try:
        move_to_jail(if_name, jid)
        return CENOERR
    except OSError as e:
        print("Error:", e.strerror, file=sys.stderr)
        return CERROR


def deattach_vnet_ifaces(j_name, if_name):
    jid = get_jail_id_by_name(j_name)
    if jid<0:
        return CENOJAIL
    try:
        print('Remove from jail', if_name)
        remove_from_jail(if_name, jid)
        return CENOERR
    except OSError as e:
        print("deattacH_vnet:", e.strerror)
        return CERROR
    
    


def remove_jail_from_name(name):
    if not name:
        return -1
    jid = get_jail_id_by_name(name)
    if jid <0:
        return CENOJAIL
    try:
        jail_remove_wrapper(jid)
        return CENOERR
    except OSError as e:
        print("remove_jail_from_name:", e.strerror)
        return CERROR
    

def jail_attach(name):
    if not name:
        return CENOJAIL
    jid = get_jail_id_by_name(name)
    if jid<0:
        return CENOJAIL
    res = jail_attach_wrapper(jid)
    if res:
        return CENOJAIL
    return CENOERR
    

def mount_jail_defvs(name, path, ruleset=4):
    root = path
    if not root:
        print('No path specified. Exiting.. ')
        return CINVALD
    if not os.path.exists(root):
        print(f"Path '{root}' doesn't exist")
        return CENOPATH
    dev_path = os.path.join(root, 'dev')
    if not os.path.exists(dev_path):
        os.mkdir(dev_path)
    if os.path.ismount(dev_path):
        return CEMNTPOT
    print("Mounting devfs on:",  dev_path)
    res = mount_devfs(dev_path, ruleset)
    if res!=0:
        errno = ctypes.get_errno()
        print("mount_jail_defvs:", os.strerror(ctypes.get_errno()))
        return CEMNTDEV
    return CENOERR

def mount_jail_tmpfs(name, path):
    root = path
    if not root:
        print('No path specified. Exiting.. ')
        return CINVALD
    if not os.path.exists(root):
        print(f"Path '{root}' doesn't exist")
        return CENOPATH
    dev_path = os.path.join(root, 'tmp')
    if not os.path.exists(dev_path):
        os.mkdir(dev_path)
    if os.path.ismount(dev_path):
        return CEMNTPOT
    print("Mounting tmpfs on:",  dev_path)
    res = mount_tmpfs(dev_path)
    if res!=0:
        errno = ctypes.get_errno()
        print("mount_jail_tmpfs:", os.strerror(ctypes.get_errno()))
        return CEMNTDEV
    return CENOERR


def unmount_jail_mounts(path):
    try:
        unmount(path)
        return CENOERR
    except OSError as e:
        print(f"unmount_jail_mounts: [Error {e.errno}] {e.strerror} ", file=sys.stderr)
        return CEUMNTERR


def unmount_jail_defvs(path):
    root = path
    dev_path = os.path.join(root, 'dev')
    try:
        unmount(dev_path)
        return CENOERR
    except OSError as e:
        print(f"unmount_jail_devfs: [Error {e.errno}] {e.strerror} ", file=sys.stderr)
        return CEUMNTERR

def unmount_jail_tmpfs(path):
    root = path
    dev_path = os.path.join(root, 'tmp')
    try:
        unmount(dev_path)
        return CENOERR
    except OSError as e:
        print(f"unmount_jail_tmpfs: [Error {e.errno}] {e.strerror} ", file=sys.stderr)
        return CEUMNTERR


def set_if_address(if_name, ip_addr, net_mask, brodcast_addr, sock=None):
    try:
        res = set_ip_address(if_name, ip_addr, net_mask, brodcast_addr, sock)
        return CENOERR
    except OSError as e:
        print(f"set_if_address: [Error {e.errno}] {e.strerror} ", file=sys.stderr)
        return CERROR
    



def set_proc_title(name):
    setup_set_proc_title()
    set_proc_title_wrapper(name)


def mount_host_to_jail(jail_path, host_path, flags):
    res= mount_nullfs(jail_path, host_path, flags)
    if res!=0:
        errno = ctypes.get_errno()
        print(f"Failed to Mount {host_path!r} to {jail_path!r}: {os.strerror(errno)}")
        return CERROR
    return CENOERR


def offset_to_netmask(offset):
    n = offset
    numeric_mask =  ((1<<n)-1)<<(32-n)
    mask= str(int((numeric_mask>>24) & ((1<<8)-1)))+'.'
    mask+=str(int((numeric_mask>>16) & ((1<<8)-1)))+'.'
    mask+=str(int((numeric_mask>>8) & ((1<<8)-1)))+'.'
    mask+=str(int(numeric_mask & ((1<<8)-1)))
    return mask



libc.sysctlbyname.argtypes = [
    ctypes.c_char_p,
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_void_p,
    ctypes.c_size_t,
]
libc.sysctlbyname.restype = ctypes.c_int


def sysctl_set_int(name: str, value: int):
    val = ctypes.c_int(value)

    ret = libc.sysctlbyname(
        name.encode(),
        None,
        None,
        ctypes.byref(val),
        ctypes.sizeof(val),
    )

    if ret != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"sysctl {name} failed: {os.strerror(err)}")
    
def convert_to_bytes(value):
    if isinstance(value, int):
        return value

    value = value.strip().upper()

    match = re.match(r"(\d+)([KMG]?B?)", value)
    if not match:
        return value

    num = int(match.group(1))
    unit = match.group(2)

    multipliers = {
        "K": 1024,
        "KB": 1024,
        "M": 1024**2,
        "MB": 1024**2,
        "G": 1024**3,
        "GB": 1024**3,
        "": 1
    }

    return num * multipliers.get(unit, 1)


def convert_to_rctl_rules(data, subject):
    if not data:
        return []
    
    resource_map = {
        "MEMORY": "memoryuse",
        "CPU_PERCENT": "pcpu",
        "PROCESS_COUNT": "maxproc",
        "OPEN_FILES": "openfiles",
        "SWAP": "swapuse",
        "CPU_TIME": "cputime"
    }

    action_map = {
        "BLOCK": "deny",
        "LOG": "log"
    }

    rules = []

    for limit in data:
        resource = limit["RESOURCE"]
        value = limit["MAX"]
        action = limit["ACTION"]

        rctl_resource = resource_map.get(resource)
        rctl_action = action_map.get(action)

        if not rctl_resource or not rctl_action:
            continue

        # convert memory-style values to bytes
        if isinstance(value, str):
            value = convert_to_bytes(value)

        rule = f"{subject}:{rctl_resource}:{rctl_action}={value}"
        rules.append(rule)

    return rules

