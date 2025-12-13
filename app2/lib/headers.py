
from .libc_ import *

IOC_VOID        =	0x20000000
IOC_OUT	        =	0x40000000
IOC_IN	        =	0x80000000
IOC_INOUT       = (IOC_IN|IOC_OUT)

IOCPARM_SHIFT   = 13
IOPARM_MASK     = (1<< IOCPARM_SHIFT)-1
IFNAMSIZ        = 16
IFGRPCOUNT      = 8

_IOC            = lambda inout, group, num, _len: (inout|((_len & IOPARM_MASK)<<16)| (ord(group)<<8) | num)
_IOW            = lambda g, n, t: _IOC(IOC_IN,    g, n, ctypes.sizeof(t))
_IOR            = lambda g, n, t: _IOC(IOC_OUT,   g, n, ctypes.sizeof(t))
_IOWR           = lambda g, n, t: _IOC(IOC_INOUT, g, n, ctypes.sizeof(t))


# Placeholder structs for ones not defined

class InAddr(ctypes.Structure):
    _fields_ = [
        ("s_addr", ctypes.c_uint32)  # IPv4 address in network byte order
    ]

class SockaddrIn(ctypes.Structure):
    _fields_ = [
        ("sin_len", ctypes.c_uint8),               # uint8_t
        ("sin_family", ctypes.c_uint8),            # sa_family_t (uint8_t on BSD)
        ("sin_port", ctypes.c_uint16),             # in_port_t (uint16_t, network byte order)
        ("sin_addr", InAddr),                      # struct in_addr
        ("sin_zero", ctypes.c_char * 8)            # padding
    ]

class Sockaddr(ctypes.Structure):
    _fields_ = [
        ("sa_len", ctypes.c_ubyte),
        ("sa_family", ctypes.c_ubyte),
        ("sa_data", ctypes.c_char * 14),
    ]

class IfAliasReq(ctypes.Structure):
    _fields_ = [
        ("ifra_name",       ctypes.c_char * IFNAMSIZ),
        ("ifra_addr",       Sockaddr),
        ("ifra_broadaddr",  Sockaddr),
        ("ifra_mask",       Sockaddr),
        ("ifra_vhid",       ctypes.c_int)
    ]



class IfreqBuffer(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_int),
        ("buffer", ctypes.c_void_p)
    ]

class IfreqNvReq(ctypes.Structure):
    _fields_ = [
        ("dummy", ctypes.c_int)  # You must define real fields here
    ]

class IfreqUnion(ctypes.Union):
    _fields_ = [
        ("ifru_addr", Sockaddr),
        ("ifru_dstaddr", Sockaddr),
        ("ifru_broadaddr", Sockaddr),
        ("ifru_buffer", IfreqBuffer),
        ("ifru_flags", ctypes.c_short * 2),
        ("ifru_index", ctypes.c_short),
        ("ifru_jid", ctypes.c_int),
        ("ifru_metric", ctypes.c_int),
        ("ifru_mtu", ctypes.c_int),
        ("ifru_phys", ctypes.c_int),
        ("ifru_media", ctypes.c_int),
        ("ifru_data", ctypes.c_void_p),
        ("ifru_cap", ctypes.c_int * 2),
        ("ifru_fib", ctypes.c_uint),
        ("ifru_vlan_pcp", ctypes.c_ubyte),
        ("ifru_nv", IfreqNvReq),
    ]

class Ifreq(ctypes.Structure):
    _fields_ = [
        ("ifr_name", ctypes.c_char * IFNAMSIZ),
        ("ifr_ifru", IfreqUnion)
    ]

class ifaddrs(ctypes.Structure):
    pass

ifaddrs._fields_ = [
    ("ifa_next", ctypes.POINTER(ifaddrs)),
    ("ifa_name", ctypes.c_char_p),
    ("ifa_flags", ctypes.c_uint),
    ("ifa_addr", ctypes.POINTER(Sockaddr)),
    ("ifa_netmask", ctypes.POINTER(Sockaddr)),
    ("ifa_dstaddr", ctypes.POINTER(Sockaddr)),
    ("ifa_data", ctypes.c_void_p)
]

class ifg_req_union(ctypes.Union):
    _fields_ = [
        ("ifgrqu_group", ctypes.c_char * IFNAMSIZ),
        ("ifgrqu_member", ctypes.c_char * IFNAMSIZ),
    ]

class ifg_req(ctypes.Structure):
    _fields_ = [
        ("ifgrq_ifgrqu", ifg_req_union),
    ]

class ifgroupreq_union(ctypes.Union):
    _fields_ = [
        ("ifgru_group", ctypes.c_char * IFNAMSIZ),
        ("ifgru_groups", ctypes.POINTER(ifg_req)),
    ]

class ifgroupreq(ctypes.Structure):
    _fields_ = [
        ("ifgr_name", ctypes.c_char * IFNAMSIZ),
        ("ifgr_len", ctypes.c_uint),
        ("ifgr_ifgru", ifgroupreq_union),
    ]

class Ifdrv(ctypes.Structure):
    _fields_ = [
        ("ifd_name", ctypes.c_char * IFNAMSIZ),     
        ("ifd_cmd", ctypes.c_ulong),                
        ("ifd_len", ctypes.c_size_t),               
        ("ifd_data", ctypes.c_void_p),              
    ]


class Ifbreq(ctypes.Structure):
    _fields_ = [
        ("ifbr_ifsname", ctypes.c_char * IFNAMSIZ),  # char ifbr_ifsname[IFNAMSIZ]
        ("ifbr_ifsflags", ctypes.c_uint32),          # uint32_t
        ("ifbr_stpflags", ctypes.c_uint32),          # uint32_t
        ("ifbr_path_cost", ctypes.c_uint32),         # uint32_t
        ("ifbr_portno", ctypes.c_uint8),             # uint8_t
        ("ifbr_priority", ctypes.c_uint8),           # uint8_t
        ("ifbr_proto", ctypes.c_uint8),              # uint8_t
        ("ifbr_role", ctypes.c_uint8),               # uint8_t
        ("ifbr_state", ctypes.c_uint8),              # uint8_t
        ("ifbr_addrcnt", ctypes.c_uint32),           # uint32_t
        ("ifbr_addrmax", ctypes.c_uint32),           # uint32_t
        ("ifbr_addrexceeded", ctypes.c_uint32),      # uint32_t
        ("pad", ctypes.c_uint8 * 32),                # uint8_t pad[32]
    ]



SIOCSIFVNET	    = _IOWR('i', 90,   Ifreq)
SIOCSIFRVNET	= _IOWR('i', 91,   Ifreq)	
SIOCIFCREATE    = _IOWR('i', 122,  Ifreq)
SIOCIFCREATE2   = _IOWR('i', 124,  Ifreq)
SIOCIFDESTROY   = _IOW( 'i', 121,  Ifreq)
SIOCSIFFLAGS	= _IOW( 'i', 16,   Ifreq)
SIOCGIFFLAGS	= _IOWR('i', 17,   Ifreq)	
SIOCGIFNETMASK	= _IOWR('i', 37,   Ifreq)
SIOCGIFGROUP	= _IOWR('i', 136,  ifgroupreq)          # get ifgroups 
SIOCSIFNAME	    = _IOW( 'i', 40,   Ifreq)	            # set IF name 
SIOCSDRVSPEC	= _IOW( 'i', 123,  Ifdrv)	            #  set driver-specific
SIOCAIFADDR	    = _IOW( 'i', 43,   IfAliasReq)          # add/chg IF alias
SIOCGIFINDEX	= _IOWR('i', 32,   Ifreq)	                # get IF index
SIOCAIFGROUP	= _IOW( 'i', 135, ifgroupreq)           # Add Group to interface
###################### BRIDGE_HEADERS ###########################

BRDGADD			= 0	    #/* add bridge member (ifbreq) */
BRDGDEL			= 1	    #/* delete bridge member (ifbreq) */
BRDGGIFFLGS		= 2	    #/* get member if flags (ifbreq) */
BRDGSIFFLGS		= 3	    #/* set member if flags (ifbreq) */
BRDGSCACHE		= 4	    #/* set cache size (ifbrparam) */
BRDGGCACHE		= 5	    #/* get cache size (ifbrparam) */
BRDGGIFS		= 6	    #/* get member list (ifbifconf) */
BRDGRTS			= 7	    #/* get address list (ifbaconf) */
BRDGSADDR		= 8	    #/* set static address (ifbareq) */
BRDGSTO			= 9	    #/* set cache timeout (ifbrparam) */
BRDGGTO			= 10	#/* get cache timeout (ifbrparam) */
BRDGDADDR		= 11	#/* delete address (ifbareq) */
BRDGFLUSH		= 12	#/* flush address cache (ifbreq) */

BRDGGPRI		= 13	#/* get priority (ifbrparam) */
BRDGSPRI		= 14	#/* set priority (ifbrparam) */
BRDGGHT			= 15	#/* get hello time (ifbrparam) */
BRDGSHT			= 16	#/* set hello time (ifbrparam) */
BRDGGFD			= 17	#/* get forward delay (ifbrparam) */
BRDGSFD			= 18	#/* set forward delay (ifbrparam) */
BRDGGMA			= 19	#/* get max age (ifbrparam) */
BRDGSMA			= 20	#/* set max age (ifbrparam) */
BRDGSIFPRIO		= 21	#/* set if priority (ifbreq) */
BRDGSIFCOST		= 22	#/* set if path cost (ifbreq) */
BRDGADDS		= 23	#/* add bridge span member (ifbreq) */
BRDGDELS		= 24	#/* delete bridge span member (ifbreq) */
BRDGPARAM		= 25	#/* get bridge STP params (ifbropreq) */
BRDGGRTE		= 26	#/* get cache drops (ifbrparam) */
BRDGGIFSSTP		= 27	#/* get member STP params list
					# * (ifbpstpconf) */
BRDGSPROTO		= 28	# /* set protocol (ifbrparam) */
BRDGSTXHC		= 29	#/* set tx hold count (ifbrparam) */
BRDGSIFAMAX		= 30	#/* set max interface addrs (ifbreq) */

###### IFFLAGS#########################
IFF_UP		= 0x1		# interface is up 
###################### MOunt OPtions##########

MNT_RDONLY	=       0x1 # read only filesystem */
MNT_SYNCHRONOUS	=   0x2 # fs written synchronously */
MNT_NOEXEC	=       0x4 # can't exec from filesystem */
MNT_NOSUID	=       0x8 # don't honor setuid fs bits */
MNT_NFS4ACLS	=   0x10 # enable NFS version 4 ACLs */
MNT_UNION	=       0x20 # union with underlying fs */
MNT_ASYNC	=       0x40 # fs written asynchronously */
MNT_SUIDDIR	=       0x100000 # special SUID dir handling */
MNT_SOFTDEP	=       0x200000 # using soft updates */
MNT_NOSYMFOLLOW	=   0x400000 # do not follow symlinks */
MNT_GJOURNAL	=   0x2000000 # GEOM journal support enabled */
MNT_MULTILABEL	=   0x4000000 # MAC support for objects */
MNT_ACLS	=       0x8000000 # ACL support enabled */
MNT_NOATIME	=       0x10000000 # dont update file access time */
MNT_NOCLUSTERR	=   0x40000000 # disable cluster read */
MNT_NOCLUSTERW	=   0x80000000 # disable cluster write */
MNT_SUJ		=       0x100000000 # using journaled soft updates */
MNT_AUTOMOUNTED	=   0x200000000 # mounted by automountd(8) */
MNT_UNTRUSTED	=   0x800000000 # filesys metadata untrusted */
