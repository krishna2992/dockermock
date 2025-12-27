import ctypes
import os
import socket

libroute = ctypes.CDLL(os.path.join(*(os.path.split(__file__)[:-1] + ('libroute.so', ))), use_errno=True)
libroute.add_route.argtypes = [
    ctypes.c_int,     # rtsock
    ctypes.c_char_p,  # destination
    ctypes.c_char_p,  # netmask
    ctypes.c_char_p   # gateway
]

libroute.add_route.restype = ctypes.c_int


def add_route( destination: str, netmask: str, gateway: str, rtsock: socket.socket=None, af=socket.AF_INET) -> int:
    # try:
    if not rtsock:
        sock = socket.socket(socket.AF_ROUTE, socket.SOCK_RAW, af)
    else:
        sock = rtsock

    try:
        res = libroute.add_route(
            sock.fileno(),
            destination.encode("utf-8"),
            netmask.encode("utf-8"),
            gateway.encode("utf-8")
        )
        if res<0:
            errno = ctypes.get_errno()
            raise OSError(errno, f"Failed to add route: {os.strerror(errno)}")

    finally:
        if not rtsock:
            print('Closing Manual sock')
            sock.close()
        



