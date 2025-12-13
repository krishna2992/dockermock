import ctypes
import os
from .lib import libc
# 1
def rctl_get_rules(subject: str, outbuflen: int = 4096) -> str:
    """
    Adds an RCTL rule on FreeBSD using the rctl_add_rule libc function.

    Args:
        rule (str): The rule to add, e.g., "user:root:memoryuse:deny=512m"
        outbuflen (int): Length of the output buffer (default: 1024)

    Returns:
        str: The content of the output buffer if successful.

    Raises:
        OSError: If the underlying system call fails.
    """
    # Prepare input and output
    inbuf = subject.encode('utf-8')
    outbuf = ctypes.create_string_buffer(outbuflen)
    
    # Call rctl_add_rule
    result = libc.rctl_get_rules(inbuf, len(inbuf)+1, outbuf, outbuflen)

    # Check result
    if result != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

    return outbuf.value.decode('utf-8')



# 2 add_rule
def rctl_add_rule(rule: str, outbuflen: int = 1024) -> str:
    """
    Adds an RCTL rule on FreeBSD using the rctl_add_rule libc function.

    Args:
        rule (str): The rule to add, e.g., "user:root:memoryuse:deny=512m"
        outbuflen (int): Length of the output buffer (default: 1024)

    Returns:
        str: The content of the output buffer if successful.

    Raises:
        OSError: If the underlying system call fails.
    """
    # Prepare input and output
    inbuf = rule.encode('utf-8')
    outbuf = ctypes.create_string_buffer(outbuflen)

    # Call rctl_add_rule
    result = libc.rctl_add_rule(inbuf, len(inbuf)+1, outbuf, outbuflen)

    # Check result
    if result != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

    return outbuf.value.decode('utf-8')

# 3
def rctl_get_limits(name: str, outbuflen: int = 4096) -> str:
    """
    Gets RCTL limits for the given subject (user, process, jail, etc).

    Args:
        name (str): The subject string (e.g., "user:root", "process:1234").
        outbuflen (int): The size of the output buffer in bytes.

    Returns:
        str: The output buffer contents (limits in plain text).

    Raises:
        OSError: If the system call fails.
    """
    # Prepare input and output
    inbuf = name.encode('utf-8')
    outbuf = ctypes.create_string_buffer(outbuflen)

    # Call the system call
    result = libc.rctl_get_limits(inbuf, len(inbuf)+1, outbuf, outbuflen)

    # Handle error
    if result != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

    return outbuf.value.decode('utf-8')

# 4
def rctl_get_racct(name: str, outbuflen: int = 4096) -> str:
    """
    Gets RACCT (resource accounting) data for a subject using rctl_get_racct().

    Args:
        name (str): The subject string (e.g., "user:root", "process:1234").
        outbuflen (int): The size of the output buffer in bytes.

    Returns:
        str: The RACCT information as a string.

    Raises:
        OSError: If the system call fails.
    """
    
    # Prepare input and output buffers
    inbuf = name.encode('utf-8')
    outbuf = ctypes.create_string_buffer(outbuflen)

    # Call the syscall
    result = libc.rctl_get_racct(inbuf, len(inbuf)+1, outbuf, outbuflen)

    # Error handling
    if result != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))

    return outbuf.value.decode('utf-8').split(',')

def rctl_remove_rule(rule: str, outbuflen: int = 1024) -> str:
    """
    Adds an RCTL rule on FreeBSD using the rctl_add_rule libc function.

    Args:
        rule (str): The rule to add, e.g., "user:root:memoryuse:deny=512m"
        outbuflen (int): Length of the output buffer (default: 1024)

    Returns:
        str: The content of the output buffer if successful.

    Raises:
        OSError: If the underlying system call fails.
    """
    # Prepare input and output
    inbuf = rule.encode('utf-8')
    outbuf = ctypes.create_string_buffer(outbuflen)

    # Call rctl_add_rule
    result = libc.rctl_remove_rule(inbuf, len(inbuf)+1, outbuf, outbuflen)

    # Check result
    if result != 0:
        errno = ctypes.get_errno()
        # print(outbuf.value.decode('utf-8'))
        raise OSError(errno, os.strerror(errno))

    return outbuf.value.decode('utf-8')


# subject = "user:0"

# rule = 'user:1001:maxproc:deny=200'
# print(rctl_add_rule(rule, 4096))
# print(rctl_get_rules(subject))
# print(dict((k, int(v))  for k, v  in  (item.split('=')  for item in rctl_get_racct(subject))))