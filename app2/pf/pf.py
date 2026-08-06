from ctypes.util import find_library
import ctypes
import functools
from sys import byteorder 
import sys
import os
import socket
from typing import List
from enum import Enum
from app2.lib import libc
libpfctl = ctypes.CDLL(find_library("pfctl"), use_errno=True)
libpf_util = ctypes.CDLL(os.path.join(*(os.path.split(__file__)[:-1] + ('libpf_util.so.2', ))), use_errno=True)

MAXPATHLEN = 1024           # MAXPATHLEN from c headers
PF_TABLE_NAME_SIZE = 32     # PF_TABLE_NAME_SIZE from c headers

PF_DEV = "/dev/pf"

class AddrType(Enum):
    PF_ADDR_ADDRMASK = 0
    PF_ADDR_NOROUTE  = 1
    PF_ADDR_DYNIFTL  = 2
    PF_ADDR_TABLE    = 3
    PF_ADDR_URPFFAILED = 4
    PF_ADDR_RANGE    = 5
    

class FilterAddr(ctypes.Structure):
    _fields_ = [
        ('type', ctypes.c_uint8),
        ('addr', ctypes.c_char * MAXPATHLEN)
    ]

libc.fflush.argtypes = [ctypes.c_void_p]
libc.fflush.restype = ctypes.c_int

def flush_stdout(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        
        try:
            return func(*args, **kwargs)
        finally:
            libc.fflush(None)
    return wrapper

libpf_util.append_rdr_rule.argtypes = [
    ctypes.c_int,          # dev
    ctypes.c_char_p,       # if_name
    ctypes.c_char_p,       # anchor
    ctypes.c_char_p,       # src
    ctypes.c_int,          # src_port
    ctypes.c_char_p,       # dst
    ctypes.c_int,          # dst_port
    ctypes.POINTER(ctypes.c_char_p),  # rdr
    ctypes.c_int,          # rdr_count
    ctypes.c_int,          # d_port
    ctypes.c_int           # af
]

libpf_util.append_rdr_rule.restype = ctypes.c_int


libpf_util.add_rdr_rule.argtypes = [
    ctypes.c_int,          # dev
    ctypes.c_char_p,       # if_name
    ctypes.c_char_p,       # anchor
    ctypes.c_char_p,       # src
    ctypes.c_int,          # src_port
    ctypes.c_char_p,       # dst
    ctypes.c_int,          # dst_port
    ctypes.POINTER(ctypes.c_char_p),  # rdr
    ctypes.c_int,          # rdr_count
    ctypes.c_int,          # d_port
    ctypes.c_int           # af
]

libpf_util.add_rdr_rule.restype = ctypes.c_int


libpf_util.add_rdr_rule_if.argtypes = [
    ctypes.c_int,          # dev
    ctypes.c_char_p,       # if_name
    ctypes.c_char_p,       # anchor
    ctypes.c_char_p,       # src
    ctypes.c_int,          # src_port
    ctypes.c_char_p,       # dst
    ctypes.c_int,          # dst_port
    ctypes.c_char_p,       # rdr_if
    ctypes.c_int,          # d_port
    ctypes.c_int           # af
]

libpf_util.add_rdr_rule_if.restype = ctypes.c_int

# 
class PfrTable(ctypes.Structure):
    _fields_ = [
        ("pfrt_anchor", ctypes.c_char * MAXPATHLEN),
        ("pfrt_name", ctypes.c_char * PF_TABLE_NAME_SIZE),
        ("pfrt_flags", ctypes.c_uint32),
        ("pfrt_fback", ctypes.c_uint8),
    ]

# 
class InAddr(ctypes.Structure):
    _fields_ = [
        ("s_addr", ctypes.c_uint32)  # IPv4 address in network byte order
    ]

# 
class U6addr(ctypes.Union):
    _fields_ = [
        ("__u6_addr8", ctypes.c_uint8*16),
        ("__u6_addr16", ctypes.c_uint16*8),
        ("__u6_addr32", ctypes.c_uint32*4)
    ]

# 
class In6Addr(ctypes.Structure):
    _fields_ = [
        ("__u6_addr", U6addr)
    ]

# 
class PfraU(ctypes.Union):
    _fields_ = [
        ("_pfra_ip4addr", InAddr),
        ("_pfra_ip6addr", In6Addr)
    ]

# 
class PfrAddr(ctypes.Structure):
    _fields_ = [
        ("pfra_u", PfraU),
        ("pfra_af", ctypes.c_int8),
        ("pfra_net", ctypes.c_int8),
        ("pfra_not", ctypes.c_int8),
        ("pfra_fback", ctypes.c_int8)
    ]

# Initialize lib function by specifying its inputs and return type
libpfctl.pfctl_table_add_addrs.argtypes = [
    ctypes.c_int,                       # dev file descriptor
    ctypes.POINTER(PfrTable),           # table name
    ctypes.POINTER(PfrAddr),            # pointer to pfr_addr array
    ctypes.c_int,                       # size of the addrs array
    ctypes.POINTER(ctypes.c_int),         # no of added rules 
    ctypes.c_int                        # flags
]

# Return type is int
libpfctl.pfctl_table_add_addrs.restypes = ctypes.c_int


libpfctl.pfctl_table_del_addrs.argtypes = [
    ctypes.c_int,                       # dev file descriptor
    ctypes.POINTER(PfrTable),           # table name
    ctypes.POINTER(PfrAddr),            # pointer to pfr_addr array
    ctypes.c_int,                       # size of the addrs array
    ctypes.POINTER(ctypes.c_int),         # no of added rules 
    ctypes.c_int                        # flags
]

# Return type is int
libpfctl.pfctl_table_del_addrs.restypes = ctypes.c_int


def pfctl_table_del_addrs( dev: int,  table_name: str,  addr: str,  size: int,  flags: int):
    # Create a Table and zero it
    pfr_table = PfrTable()
    ctypes.memset(ctypes.byref(pfr_table), 0, ctypes.sizeof(PfrTable))

    # Add table name
    pfr_table.pfrt_name = table_name.encode("utf-8").ljust(PF_TABLE_NAME_SIZE, b'\x00')

    # Convert IP String to in_addr
    packed_ip = socket.inet_pton(socket.AF_INET, addr)  
    ip_uint32 = ctypes.c_uint32(int.from_bytes(packed_ip, byteorder=byteorder))
    in_addr = InAddr(s_addr=ip_uint32)

    # Create PfrAddt
    pfr_addr = PfrAddr()
    ctypes.memset(ctypes.byref(pfr_addr), 0, ctypes.sizeof(PfrAddr))
    
    # Add Values to Structure
    pfr_addr.pfra_u._pfra_ip4addr = in_addr
    pfr_addr.pfra_af    = socket.AF_INET.value
    pfr_addr.pfra_net   = 32

    # Store count of added address
    x = ctypes.c_int(0) 
    
    # Call pfctl function
    res = libpfctl.pfctl_table_del_addrs(
        ctypes.c_int(dev),                  # dev
        ctypes.byref(pfr_table),            # pfr_table
        ctypes.byref(pfr_addr),             # pfr_addr
        ctypes.c_int(size),                 # no. of address
        ctypes.byref(x),                    # store no. of  addrs added
        ctypes.c_int(flags)                 # flags
    )
    
    # 
    print(f'removed {x.value} address')

    # Check if call is succesful
    if res:
        # Check error and raise Exception
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_table_del_addrs: {os.strerror(errno)}")

# Higher Level Function to add rule to pf table
def pfctl_table_add_addrs( dev: int,  table_name: str,  addr: str,    flags: int):
    addr = addr.split('/')
    
    if len(addr)>1:
        mask = int(addr[1])
    else:
        mask = 32
    addr = addr[0]
    # Create a Table and zero it
    pfr_table = PfrTable()
    ctypes.memset(ctypes.byref(pfr_table), 0, ctypes.sizeof(PfrTable))

    # Add table name
    pfr_table.pfrt_name = table_name.encode("utf-8").ljust(PF_TABLE_NAME_SIZE, b'\x00')

    # Convert IP String to in_addr
    packed_ip = socket.inet_pton(socket.AF_INET, addr)  
    ip_uint32 = ctypes.c_uint32(int.from_bytes(packed_ip, byteorder=byteorder))
    in_addr = InAddr(s_addr=ip_uint32)

    # Create PfrAddt
    pfr_addr = PfrAddr()
    ctypes.memset(ctypes.byref(pfr_addr), 0, ctypes.sizeof(PfrAddr))
    
    # Add Values to Structure
    pfr_addr.pfra_u._pfra_ip4addr = in_addr
    pfr_addr.pfra_af    = socket.AF_INET.value
    # pfr_addr.pfra_net   = 32
    pfr_addr.pfra_net   = mask

    # Store count of added address
    x = ctypes.c_int(0) 
    
    # Call pfctl function
    res = libpfctl.pfctl_table_add_addrs(
        ctypes.c_int(dev),                  # dev
        ctypes.byref(pfr_table),            # pfr_table
        ctypes.byref(pfr_addr),             # pfr_addr
        ctypes.c_int(size),                 # no. of address
        ctypes.byref(x),                    # store no. of  addrs added
        ctypes.c_int(flags)                 # flags
    )
    # 

    print(f"added {x.value} address")
    
    # Check if call is succesful
    if res:
        # Check error and raise Exception
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_table_add_addrs: {os.strerror(errno)}")
    


def pfctl_table_add_addrs_list( table_name: str, addrs: List[str], flags: int):
    size = len(addrs)
    if size == 0:
        raise ValueError("No addresses provided.")

    # Create and initialize the table
    pfr_table = PfrTable()
    ctypes.memset(ctypes.byref(pfr_table), 0, ctypes.sizeof(PfrTable))
    pfr_table.pfrt_name = table_name.encode("utf-8").ljust(PF_TABLE_NAME_SIZE, b'\x00')

    # Create an array of PfrAddr structures
    PfrAddrArray = PfrAddr * size
    addr_array = PfrAddrArray()

    for i, addr in enumerate(addrs):
        addr = addr.split('/')
        packed_ip = socket.inet_pton(socket.AF_INET, addr[0])
        ip_uint32 = ctypes.c_uint32(int.from_bytes(packed_ip, byteorder=byteorder))
        in_addr = InAddr(s_addr=ip_uint32)

        pfr_addr = PfrAddr()
        ctypes.memset(ctypes.byref(pfr_addr), 0, ctypes.sizeof(PfrAddr))
        pfr_addr.pfra_u._pfra_ip4addr = in_addr
        pfr_addr.pfra_af = socket.AF_INET
        pfr_addr.pfra_net = int(addr[1]) if len(addr)>1 else 32

        addr_array[i] = pfr_addr

    # Store count of added address
    x = ctypes.c_int(0)
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:
    # Call pfctl function
        res = libpfctl.pfctl_table_add_addrs(
            ctypes.c_int(dev),
            ctypes.byref(pfr_table),
            ctypes.cast(addr_array, ctypes.POINTER(PfrAddr)),
            ctypes.c_int(size),
            ctypes.byref(x),
            ctypes.c_int(flags)
        )
    finally:
        os.close(dev)

    print(f"added {x.value} addresses")

    if res:
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_table_add_addrs: {os.strerror(err)}")




def pfctl_table_del_addr_list(table_name: str, addrs: List[str], flags: int):
    size = len(addrs)
    if size == 0:
        raise ValueError("No addresses provided.")

    
    # Create and initialize the table
    pfr_table = PfrTable()
    ctypes.memset(ctypes.byref(pfr_table), 0, ctypes.sizeof(PfrTable))
    pfr_table.pfrt_name = table_name.encode("utf-8").ljust(PF_TABLE_NAME_SIZE, b'\x00')

    # Create an array of PfrAddr structures
    PfrAddrArray = PfrAddr * size
    addr_array = PfrAddrArray()

    for i, addr in enumerate(addrs):
        packed_ip = socket.inet_pton(socket.AF_INET, addr)
        ip_uint32 = ctypes.c_uint32(int.from_bytes(packed_ip, byteorder=byteorder))
        in_addr = InAddr(s_addr=ip_uint32)

        pfr_addr = PfrAddr()
        ctypes.memset(ctypes.byref(pfr_addr), 0, ctypes.sizeof(PfrAddr))
        pfr_addr.pfra_u._pfra_ip4addr = in_addr
        pfr_addr.pfra_af = socket.AF_INET
        pfr_addr.pfra_net = 32

        addr_array[i] = pfr_addr

    # Store count of removed addresses
    x = ctypes.c_int(0)

    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        
        # Call pfctl function to delete addresses
        res = libpfctl.pfctl_table_del_addrs(
            ctypes.c_int(dev),
            ctypes.byref(pfr_table),
            ctypes.cast(addr_array, ctypes.POINTER(PfrAddr)),
            ctypes.c_int(size),
            ctypes.byref(x),
            ctypes.c_int(flags)
        )
    finally:
        # Close anyway
        os.close(dev)

    print(f"removed {x.value} address(es)")

    if res:
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_table_del_addrs: {os.strerror(err)}")


def pfctl_add_rdr_rule(if_name:str, src_address: str, dst_address: str, rdr_address: List[str], rdr_port: int, src_port: int=-1, dst_port:int=-1, af=socket.IPPROTO_TCP):
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        

        c_ip_list = (ctypes.c_char_p * len(rdr_address))()

        for i, ip in enumerate(rdr_address):
            c_ip_list[i] = ip.encode('utf-8')
        
        res = libpf_util.add_rdr_rule(
            dev, 
            if_name.encode(), 
            f"cni-rdr/{if_name}".encode(), 
            src_address.encode(), 
            src_port,
            dst_address.encode(), 
            dst_port, 
            c_ip_list, 
            len(rdr_address), 
            rdr_port,
            af
        )
    finally:
        # Close anyway
        os.close(dev)
    
    if res:
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_add_rdr_error: {os.strerror(err)}")



def pfctl_append_rdr_rule(if_name:str, anchor:str, src_address: str, dst_address: str, rdr_address: List[str], rdr_port: int, src_port: int=-1, dst_port:int=-1, af=socket.IPPROTO_TCP):
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        

        c_ip_list = (ctypes.c_char_p * len(rdr_address))()

        for i, ip in enumerate(rdr_address):
            c_ip_list[i] = ip.encode('utf-8')
        
        res = libpf_util.append_rdr_rule(
            dev, 
            if_name.encode(), 
            anchor.encode(), 
            src_address.encode(), 
            src_port,
            dst_address.encode(), 
            dst_port, 
            c_ip_list, 
            len(rdr_address), 
            rdr_port,
            af
        )
    finally:
        # Close anyway
        os.close(dev)
    
    if res:
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_add_rdr_error: {os.strerror(err)}")


def pfctl_add_rdr_rule_if(if_name:str, src_address: str, dst_address: str,  rdr_port: int, src_port: int=-1, dst_port:int=-1, af=socket.IPPROTO_TCP):
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        

        res = libpf_util.add_rdr_rule_if(
            dev, 
            if_name.encode(), 
            f"cni-rdr/{if_name}".encode(), 
            src_address.encode(), 
            src_port,
            dst_address.encode(), 
            dst_port, 
            if_name.encode(), 
            rdr_port,
            af            
        )
    finally:
        # Close anyway
        os.close(dev)
    
    if res:
        err = ctypes.get_errno()
        raise OSError(erro, f"pfctl_add_rdr_error: {os.strerror(err)}")


libpf_util.add_addressList_to_pool.argtypes = [
    ctypes.c_int,                                 # int dev
    ctypes.c_char_p,                              # char* path
    ctypes.c_int,                                 # int r_num
    ctypes.POINTER(ctypes.c_char_p),              # char* addrList[]
    ctypes.c_int                                  # int n_addr
]

libpf_util.add_addressList_to_pool.restype = ctypes.c_int  # int return type


def pfctl_add_addressList_to_pool(path: str, r_num: int, addr_list: list[str]) -> int:
    """Python wrapper for C function add_addressList_to_pool."""

    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        
        n_addr = len(addr_list)

        # Convert Python list of strings to a C array of c_char_p
        addr_array = (ctypes.c_char_p * n_addr)(
            *[s.encode('utf-8') for s in addr_list]
        )

        # Call the C function
        res = libpf_util.add_addressList_to_pool(
            ctypes.c_int(dev),
            ctypes.c_char_p(path.encode('utf-8')),
            ctypes.c_int(r_num),
            addr_array,
            ctypes.c_int(n_addr)
        )
    finally:
        os.close(dev)


    if res:
        err = ctypes.get_errno()
        raise OSError(erro, f"pfctl_add_addressList_to_pool: {os.strerror(err)}")


libpf_util.remove_addressList_from_pool.argtypes = [
    ctypes.c_int,                                 # int dev
    ctypes.c_char_p,                              # char* path
    ctypes.c_int,                                 # int r_num
    ctypes.POINTER(ctypes.c_char_p),              # char* addrList[]
    ctypes.c_int                                  # int n_addr
]
libpf_util.remove_addressList_from_pool.restype = ctypes.c_int  # int return type


def pfctl_remove_addressList_from_pool( path: str, r_num: int, addr_list: list[str]) -> int:
    
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        

    try:


        n_addr = len(addr_list)

        # Convert Python list of strings to a C array of c_char_p
        addr_array = (ctypes.c_char_p * n_addr)(
            *[s.encode('utf-8') for s in addr_list]
        )

        # Call the C function
        res = libpf_util.remove_addressList_from_pool(
            ctypes.c_int(dev),
            ctypes.c_char_p(path.encode('utf-8')),
            ctypes.c_int(r_num),
            addr_array,
            ctypes.c_int(n_addr)
        )
    finally:
        os.close(dev)

    if res:
        err = ctypes.get_errno()
        raise OSError(erro, f"pfctl_add_addressList_to_pool: {os.strerror(err)}")


libpf_util.append_rdr_rule_src_if.argtypes = [
    ctypes.c_int,                     # int dev
    ctypes.c_char_p,                  # char* if_name
    ctypes.c_char_p,                  # char* anchor
    ctypes.POINTER(FilterAddr),       # filter_addr* src
    ctypes.c_int,                     # int src_port
    ctypes.POINTER(FilterAddr),       # filter_addr* dst
    ctypes.c_int,                     # int dst_port
    ctypes.POINTER(ctypes.c_char_p),  # char** rdr
    ctypes.c_int,                     # int rdr_count
    ctypes.c_int,                     # int d_port
    ctypes.c_int                      # int proto
]

# Define return type
libpf_util.append_rdr_rule_src_if.restype = ctypes.c_int

def pfctl_append_rdr_rule_src_if(if_name:str, anchor:str, src_if: str, dst_address: str,  rdr_address: List[str], rdr_port: int, src_port: int=-1, dst_port:int=-1, af=socket.IPPROTO_TCP):
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        
        src = FilterAddr()
        dst = FilterAddr()
        src.type = AddrType.PF_ADDR_ADDRMASK.value
        src.addr = src_if.encode()
        dst.type = AddrType.PF_ADDR_DYNIFTL.value
        dst.addr = dst_address.encode()


        c_ip_list = (ctypes.c_char_p * len(rdr_address))()

        for i, ip in enumerate(rdr_address):
            c_ip_list[i] = ip.encode('utf-8')

        res = libpf_util.append_rdr_rule_src_if(
            dev, 
            if_name.encode(), 
            anchor.encode(), 
            src, 
            src_port,
            dst, 
            dst_port, 
            c_ip_list,
            len(rdr_address), 
            rdr_port,
            af            
        )
    finally:
        # Close anyway
        print('Closing dev')
        os.close(dev)
    
    if res:
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_append_rdr_rule_src_if: {os.strerror(err)}")


libpf_util.append_rdr_rule_generic.argtypes = [
    ctypes.c_int,                     # int dev
    ctypes.c_char_p,                  # char* if_name
    ctypes.c_char_p,                  # char* anchor
    ctypes.POINTER(FilterAddr),       # filter_addr* src
    ctypes.c_int,                     # int src_port
    ctypes.POINTER(FilterAddr),       # filter_addr* dst
    ctypes.c_int,                     # int dst_port
    ctypes.POINTER(ctypes.c_char_p),  # char** rdr
    ctypes.c_int,                     # int rdr_count
    ctypes.c_int,                     # int d_port
    ctypes.c_int,                     # int proto
    ctypes.c_int                      # int quick
]

# Define return type
libpf_util.append_rdr_rule_generic.restype = ctypes.c_int


def pfctl_append_rdr_rule_generic(if_name:str, anchor:str, src: str, dst: str,  rdr_address: List[str], rdr_port: int, src_port: int=-1, dst_port:int=-1, af=socket.IPPROTO_TCP, quick=0):
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        
        src_filter = FilterAddr()
        dst_filter = FilterAddr()

        if src.startswith('(') and src.endswith(')'):
            src_filter.type = AddrType.PF_ADDR_DYNIFTL.value
            src_filter.addr = src[1:-1].encode()
        elif src.startswith('<') and src.endswith('>'):
            src_filter.type = AddrType.PF_ADDR_TABLE.value
            src_filter.addr = src[1:-1].encode()
        else:
            src_filter.type = AddrType.PF_ADDR_ADDRMASK.value
            src_filter.addr = src.encode()

        if dst.startswith('(') and dst.endswith(')'):
            dst_filter.type = AddrType.PF_ADDR_DYNIFTL.value
            dst_filter.addr = dst[1:-1].encode()
        elif dst.startswith('<') and dst.endswith('>'):
            dst_filter.type = AddrType.PF_ADDR_TABLE.value
            dst_filter.addr = dst[1:-1].encode()
        else:
            dst_filter.type = AddrType.PF_ADDR_ADDRMASK.value
            dst_filter.addr = dst.encode()

        c_ip_list = (ctypes.c_char_p * len(rdr_address))()

        for i, ip in enumerate(rdr_address):
            c_ip_list[i] = ip.encode('utf-8')

        res = libpf_util.append_rdr_rule_generic(
            dev, 
            if_name.encode(), 
            anchor.encode(), 
            src_filter, 
            src_port,
            dst_filter, 
            dst_port, 
            c_ip_list,
            len(rdr_address), 
            rdr_port,
            af,
            quick            
        )
    finally:
        # Close anyway
        print('Closing dev')
        os.close(dev)
    
    if res:
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_append_rdr_rule_generic: {os.strerror(err)}")


# int clear_ruleset(int dev, char* anchor)
libpf_util.clear_ruleset.argtypes = [
    ctypes.c_int,                     # int dev
    ctypes.c_char_p,                  # char* anchor
    
]

# Define return type
libpf_util.clear_ruleset.restype = ctypes.c_int

@flush_stdout
def pfctl_clear_ruleset(anchor:str):
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        
        res = libpf_util.clear_ruleset(
            dev, 
            anchor.encode()
        )
    finally:
        # Close anyway
        print('Closing dev')
        os.close(dev)
    
    if res:
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_clear_ruleset: {os.strerror(err)}")
    print("Ruleset cleared succesfully")


libpf_util.remove_rdr_port_rule.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
libpf_util.remove_rdr_port_rule.restype  = ctypes.c_int

@flush_stdout
def pfctl_remove_rdr_port_rule(anchor: str, port: int, proto: int) -> int:
    """
    Python wrapper for: int remove_rdr_port_rule(int dev, char* anchor, int port, int proto)
    """
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        
        anchor_bytes = anchor.encode("utf-8") if anchor is not None else None
        res =  libpf_util.remove_rdr_port_rule(
            dev, 
            anchor_bytes, 
            port, 
            proto
        )
    finally:
        # Close anyway
        print('Closing dev')
        os.close(dev)
    
    if res:
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_clear_ruleset: {os.strerror(err)}")
    print("Ruleset cleared succesfully")


libpf_util.remove_nat_port_rule.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
libpf_util.remove_nat_port_rule.restype  = ctypes.c_int

@flush_stdout
def pfctl_remove_nat_port_rule(anchor: str, port: int, proto: int) -> int:
    """
    Python wrapper for: int remove_rdr_port_rule(int dev, char* anchor, int port, int proto)
    """
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        
        anchor_bytes = anchor.encode("utf-8") if anchor is not None else None
        res =  libpf_util.remove_nat_port_rule(
            dev, 
            anchor_bytes, 
            port, 
            proto
        )
    finally:
        # Close anyway
        print('Closing dev')
        os.close(dev)
    
    if res:
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_nat_port_clear: {os.strerror(err)}")
    print("Ruleset cleared succesfully")


libpf_util.clear_nat_ruleset.restype = ctypes.c_int

@flush_stdout
def pfctl_clear_nat_ruleset(anchor:str):
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        
        res = libpf_util.clear_nat_ruleset(
            dev, 
            anchor.encode()
        )
    finally:
        # Close anyway
        print('Closing dev')
        os.close(dev)
    
    if res:
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_clear_nat_ruleset: {os.strerror(err)}")
    print("Ruleset cleared succesfully")


libpf_util.append_nat_rule_generic.argtypes = [
    ctypes.c_int,                     # int dev
    ctypes.c_char_p,                  # char* if_name
    ctypes.c_char_p,                  # char* anchor
    ctypes.POINTER(FilterAddr),       # filter_addr* src
    ctypes.c_int,                     # int src_port
    ctypes.POINTER(FilterAddr),       # filter_addr* dst
    ctypes.c_int,                     # int dst_port
    ctypes.POINTER(ctypes.c_char_p),  # char** rdr
    ctypes.c_int,                     # int rdr_count
    ctypes.c_int,                     # int d_port
    ctypes.c_int,                     # int proto
    ctypes.c_int                      # int quick
]

# Define return type
libpf_util.append_nat_rule_generic.restype = ctypes.c_int

@flush_stdout
def pfctl_append_nat_rule_generic(if_name:str, anchor:str, src: str, dst: str,  rdr_address: List[str], rdr_port: int=-1, src_port: int=-1, dst_port:int=-1, af=socket.IPPROTO_TCP, quick=0):
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        
        src_filter = FilterAddr()
        dst_filter = FilterAddr()

        if src.startswith('(') and src.endswith(')'):
            src_filter.type = AddrType.PF_ADDR_DYNIFTL.value
            src_filter.addr = src[1:-1].encode()
        elif src.startswith('<') and src.endswith('>'):
            src_filter.type = AddrType.PF_ADDR_TABLE.value
            src_filter.addr = src[1:-1].encode()
        else:
            src_filter.type = AddrType.PF_ADDR_ADDRMASK.value
            src_filter.addr = src.encode()

        if dst.startswith('(') and dst.endswith(')'):
            dst_filter.type = AddrType.PF_ADDR_DYNIFTL.value
            dst_filter.addr = dst[1:-1].encode()
        elif dst.startswith('<') and dst.endswith('>'):
            dst_filter.type = AddrType.PF_ADDR_TABLE.value
            dst_filter.addr = dst[1:-1].encode()
        else:
            dst_filter.type = AddrType.PF_ADDR_ADDRMASK.value
            dst_filter.addr = dst.encode()

        c_ip_list = (ctypes.c_char_p * len(rdr_address))()

        for i, ip in enumerate(rdr_address):
            c_ip_list[i] = ip.encode('utf-8')

        res = libpf_util.append_nat_rule_generic(
            dev, 
            if_name.encode(), 
            anchor.encode(), 
            src_filter, 
            src_port,
            dst_filter, 
            dst_port, 
            c_ip_list,
            len(rdr_address), 
            rdr_port,
            af,
            quick            
        )
    finally:
        # Close anyway
        print('Closing dev')
        os.close(dev)
    
    if res:
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_append_nat_rule_generic: {os.strerror(err)}")

libpf_util.append_nat_rule_src_if.argtypes = [
    ctypes.c_int,                     # int dev
    ctypes.c_char_p,                  # char* if_name
    ctypes.c_char_p,                  # char* anchor
    ctypes.POINTER(FilterAddr),       # filter_addr* src
    ctypes.c_int,                     # int src_port
    ctypes.POINTER(FilterAddr),       # filter_addr* dst
    ctypes.c_int,                     # int dst_port
    ctypes.POINTER(ctypes.c_char_p),  # char** rdr
    ctypes.c_int,                     # int rdr_count
    ctypes.c_int,                     # int d_port
    ctypes.c_int                      # int proto
]

# Define return type
libpf_util.append_nat_rule_src_if.restype = ctypes.c_int

@flush_stdout
def pfctl_append_nat_rule_src_if(if_name:str, anchor:str, src_if: str, dst_address: str,  rdr_address: List[str], rdr_port: int, src_port: int=-1, dst_port:int=-1, af=socket.IPPROTO_TCP):
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        
        src = FilterAddr()
        dst = FilterAddr()
        src.type = AddrType.PF_ADDR_ADDRMASK.value
        src.addr = src_if.encode()
        dst.type = AddrType.PF_ADDR_DYNIFTL.value
        dst.addr = dst_address.encode()


        c_ip_list = (ctypes.c_char_p * len(rdr_address))()

        for i, ip in enumerate(rdr_address):
            c_ip_list[i] = ip.encode('utf-8')

        res = libpf_util.append_rdr_rule_src_if(
            dev, 
            if_name.encode(), 
            anchor.encode(), 
            src, 
            src_port,
            dst, 
            dst_port, 
            c_ip_list,
            len(rdr_address), 
            rdr_port,
            af            
        )
    finally:
        # Close anyway
        print('Closing dev')
        os.close(dev)
    
    if res:
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_append_rdr_rule_src_if: {os.strerror(err)}")

libpf_util.enable.argtypes = [
    ctypes.c_int                     # int dev
]
libpf_util.enable.restype = ctypes.c_int

@flush_stdout
def pfctl_enable():
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        
        res = libpf_util.enable(
            dev
        )
    finally:
        # Close anyway
        print('Closing dev')
        os.close(dev)
    
    if res:
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_enable: {os.strerror(err)}")


libpf_util.disable.argtypes = [
    ctypes.c_int                     # int dev
]
libpf_util.disable.restype = ctypes.c_int

@flush_stdout
def pfctl_disable():
    dev = os.open(PF_DEV, os.O_RDWR)
    if(dev == -1):
        errno = ctypes.get_errno()
        raise OSError(errno, f"Failed to open: {PF_DEV}")        
    try:        
        res = libpf_util.disable(
            dev
        )
    finally:
        # Close anyway
        print('Closing dev')
        os.close(dev)
    
    if res:
        err = ctypes.get_errno()
        raise OSError(err, f"pfctl_enable: {os.strerror(err)}")
