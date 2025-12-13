import sys, json
import ctypes
import traceback
import time
from app2.Jail_ import Jail 
from app2.wrappers import rfork_wrapper
import requests as r
from datetime import datetime 
import subprocess
import os
import subprocess
import ipaddress

def redirect_io(stdout_path="/var/log/app.log", stderr_path=None, stdin_path="/dev/null"):
    """Redirect stdout, stderr to log file and stdin to /dev/null."""
    if stderr_path is None:
        stderr_path = stdout_path

    # sys.stdout.flush()
    # sys.stderr.flush()

    fd_out = os.open(stdout_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    fd_in  = os.open(stdin_path, os.O_RDONLY)

    os.dup2(fd_in, 0)   
    os.dup2(fd_out, 1)     
    os.dup2(fd_out, 2)  
    os.close(fd_in)      
    os.close(fd_out)     

def redirect_standard_fds(logfile_path):
    """Redirect stdin to /dev/null, and stdout/stderr to a logfile."""
    # Redirect stdin to /dev/null
    devnull_fd = os.open("/dev/null", os.O_RDONLY)
    os.dup2(devnull_fd, 0)  # stdin
    if devnull_fd > 2:
        os.close(devnull_fd)

    # Redirect stdout and stderr to logfile
    log_fd = os.open(logfile_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(log_fd, 1)  # stdout
    os.dup2(log_fd, 2)  # stderr
    if log_fd > 2:
        os.close(log_fd)

def register_ports(network, ports):
    name = network['name']
    ip   = network['ip']
    for i in range(len(ports)):
        ports[i]['rdr'] = [ip]
    
    data = {'network':network['name'], 'ports':ports}
    print(data)
    try:
        res = r.post(f'http://localhost:5000/api/ports', json=data)
    except Exception as e:
        traceback.print_tb(e.__traceback__)
    


def notity_status(name, exit_code, msg):
    data = {
        'name':name,
        'exit_code':exit_code,
        'message':msg
    }
    res = r.post(f'http://localhost:5000/api/container/{name}/exit_code', json=data)
    return res.status_code

def register_subnet(network, subnet):
    data = {
        'network':network,
        'subnet': subnet
    }

    res = r.post(f'http://localhost:5000/subnet', json=data)
    return res.status_code


def register_dns_entry(network, domain, ip):
    data = {
        'network':network,
        'domain': domain,
        'ip':ip
    }

    res = r.post(f'http://localhost:5000/dns', json=data)
    return res.status_code


def register_jail_network(networks):
    if not networks:
        return
    if networks[0]['driver'] == 'host':
        return
    for network in networks:
        ip = ipaddress.ip_interface(network.get('ip')+'/'+str(network.get('prefix')))
        subnet = f'{network.get("subnet")}/{network.get("prefix")}'
        net_if = network.get('name') or 'default'

        print(f"Registring subnet {subnet} for network {net_if!r}")
        res = register_subnet(net_if, subnet)
        if res != 201:
            raise Exception('Failed to register subnet')

        print(f'Registering {ip} for  {name}')
        res = register_dns_entry(net_if, name, str(ip.ip))
        if res != 201:
            raise Exception('Failed to register ip')
            

def start_container(ID, name, jail_json):
    print(jail_json[1])
    print(jail_json[0])
    jail = Jail(ID, name, True, jail_json[1], jail_json[0])
    try:
        jail.create_jail()
        
        if jail.jid<0:
            print(os.strerror(ctypes.get_errno()))
            notity_status(name, 100, "Failed to Create JAIL")
            return -1
        networks = jail_json[0]['networks']
        print('Registring networks')
        if networks:
            register_jail_network(networks)
            print(f'Ports: {jail_json[0].get("ports")}')
            if  jail_json[0].get('ports'):
                ports = jail_json[0]['ports']
                for network in networks:
                    print(f'Registering {ports} for {network}')
                    register_ports(network, jail_json[0]['ports'])
        
    except Exception as e:
        print("Got exception", e)
        jail.destroy_jail()
        notity_status(name, 100, "Failed to CREATE EPAIR")
        raise e
        
    pid = os.fork()
    if pid == 0:
        try:
            # redirect_io(stdout_path='/tmp/parent.log')
            redirect_standard_fds('parent.log')
            print(f"[CHILD] PID: {os.getpid()}")
            jail.child()
        except Exception as e:
            # Redirect to stderr (which now points to log file)
            print(f"[Child] Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"[Parent] Forked child with PID {pid}, ppid: {os.getpid()}")
        _, status = os.waitpid(pid, 0)
        exit_code = os.WEXITSTATUS(status)
        print(f"[Parent] Child exited with code {exit_code}")
        print(f"[Parent] Destroying jail with JID: {jail.jid}")
        jail.destroy_jail()
        notity_status(name, exit_code, f'Exited on: {datetime.now().isoformat()}')   
        print(f'Container Stopped Succesfully') 
        exit(0)



def transform_json(data):
    config = []
    data["fs_mounts"]= [
        "devfs",
        "tmpfs"
    ]
    config.append(data)
    jail = {}

    # Name of Jail
    jail['name'] = data['name']

    # Hostname for Jail
    jail['host.hostname'] = data['name'] + '.jail'

    # Path of Jail FS
    jail['path'] = os.path.join(data['path'], 'root')

    # Jail Devfs Ruleset
    jail['devfs_ruleset'] = 4

    # Jail Networking stack
    if 'networks' in data and data['networks'] and data['networks'][0]['driver'] == 'host':
        # Host Jail
        jail['ip4'] = 2
    else:
        # Vnet Jail
        jail['vnet'] = True
    
    # Add IPC to  jail
    jail['sysvshm'] = 1
    jail['sysvmsg'] = 1
    jail['sysvsem'] = 1

    # Make jail persist for cleanup
    jail['persist'] = True

    config.append(jail)
    return config

    pass
if __name__ == '__main__':
    if len(sys.argv) < 2:
        exit(-1)
    pid = os.fork()
    if pid > 0:
        # Exit from parent
        sys.exit(0)

    # Decouple from parent environment
    os.setsid()

    # Second fork
    pid = os.fork()
    if pid > 0:
        # Exit from second parent
        sys.exit(0)
    # os.chdir("/home/krishna/Projects/JAIL/")
    redirect_standard_fds('parent.log')
    # prev_std, prev_stderr, sys.stdout, sys.stderr
    sys.stdout = os.fdopen(1, "w", buffering=1)
    sys.stderr = os.fdopen(2, "w", buffering=1)
    print(sys.argv)

    name = sys.argv[1]
    res = r.get(f'http://localhost:5000/api/container/{name}')
    if res.status_code != 200:
        print(res.content)
        print('Existing...')
        exit(-1)
    data = res.json()
    data = transform_json(data)  
    print(json.dumps(data))  
    print('Calling Container start')
    start_container(1, name, data)
    

