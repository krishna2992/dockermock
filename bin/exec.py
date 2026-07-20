#!/usr/bin/env python3

import os
import sys
import requests as r
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app2.helpers import jail_attach, get_jail_id_by_name
import ctypes

def container_exec(container, command):
    jail_name = container.get('name')
    if not jail_name:
        print("Name cannot be null")
        sys.exit(-1)
    
    if(container.get('status') != 'running'):
        print('Container is not running')
        exit(-1)    
    res = jail_attach(jail_name)
    if(res < 0):
        print(f'Failed to exec into container: {os.strerror(ctypes.get_errno())}')
        sys.exit(-1)
    
    os.chdir(container.get('workingDir', '/'))
    env = container.get('env', {})
    env.setdefault('USER', container.get('user', 'root'))
    env.setdefault('HOSTNAME', jail_name+'.jail')
    env.setdefault('HOME', '/root')
    env.setdefault('SHELL', '/bin/sh')
    env.setdefault('TERM', 'xterm')
    env.setdefault('PS1',"\\u@\\h:\\w $ ")


    try:
        os.execvpe(command[0], command, env)
    except FileNotFoundError as e:
        print(f'OCI Error: {e.strerror}: {e.filename.decode()!r}' )
    except Exception as  e:
        print(f'OCI Error: {e.strerror}:' )
    sys.exit(-1)


if __name__ == '__main__':
    if len(sys.argv)<3:
        print("Usage: python exec.py <jail_name> <executable> <args>")
        exit(1)

    jail_name =    sys.argv[1]
    executable = sys.argv[2]
    res = r.get(f'http://localhost:5000/api/container/{jail_name}')

    if res.status_code!=200:
        print(res.content)
        exit(1)

    data = res.json()
    container_exec(data)