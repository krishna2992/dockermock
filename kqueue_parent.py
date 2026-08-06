import sys, json
import ctypes
import traceback
from app2.Jail_ import Jail 
from app2.wrappers import rfork_wrapper
from app2.JailManager_ import RFPROC, RFCFDG
import socket
import select
import signal
import json
import requests as r
from datetime import datetime 
import os
import ipaddress
import logging

logger = logging.getLogger(__name__)
# Store Jail Object against Child PID
JAIL_DICT = {}

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


def register_jail_network(name, networks):
    if not networks:
        return
    if networks[0]['driver'] == 'host':
        return
    for network in networks:
        ip = ipaddress.ip_interface(network.get('ip')+'/'+str(network.get('prefix')))
        subnet = f'{network.get("subnet")}/{network.get("prefix")}'
        net_if = network.get('name') or 'default'

        logger.debug(f"Registring subnet {subnet} for network {net_if!r}")
        res = register_subnet(net_if, subnet)
        if res != 201:
            raise Exception('Failed to register subnet')

        logger.debug(f'Registering {ip} for  {name}')
        res = register_dns_entry(net_if, name, str(ip.ip))
        if res != 201:
            raise Exception('Failed to register ip')
            

def start_container(ID, name, jail_json) -> int:
    jail = Jail(ID, name, True, jail_json[1], jail_json[0])
    try:
        jail.create_jail()
        
        if jail.jid<0:
            logger.error(f'{os.strerror(ctypes.get_errno())}')
            notity_status(name, 100, "Failed to Create JAIL")
            return -1
        networks = jail_json[0]['networks']
        logger.debug('Registring networks')
        if networks:
            register_jail_network(name, networks)
            logger.debug(f'Ports: {jail_json[0].get("ports")}')
            if  jail_json[0].get('ports'):
                ports = jail_json[0]['ports']
                for network in networks:
                    logger.debug(f'Registering {ports} for {network}')
                    register_ports(network, jail_json[0]['ports'])
        
    except Exception as e:
        logger.error(f"Got exception: {str(e)}")
        jail.destroy_jail()
        notity_status(name, 100, "Failed to CREATE EPAIR")
        traceback.print_exception(type(e), e, e.__traceback__)
        return -1
        
    pid = rfork_wrapper(RFPROC|RFCFDG)
    if pid == 0:
        try:
            # redirect_io(stdout_path='/tmp/parent.log')
            os.setsid()
            redirect_standard_fds('parent.log')
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            logger.info(f"[CHILD] PID: {os.getpid()}")
            jail.child()
        except Exception as e:
            # Redirect to stderr (which now points to log file)
            logger.error(f"[Child] Error: {e}")
            sys.exit(1)
    
    logger.info(f"[Parent] Forked child with PID {pid}, ppid: {os.getpid()}")
    # Store jail object and use it for cleaning
    global JAIL_DICT
    JAIL_DICT[pid] = jail    
    # return pid and listen for exit event
    return pid
    



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

    # Default Secure level
    jail['securelevel'] = 2

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


def process_container(name):
    res = r.get(f'http://localhost:5000/api/container/{name}')
    if res.status_code != 200:
        logger.error(res.text)
        return -1
    data = res.json()
    data = transform_json(data)  
    logger.info('Calling Container start')
    return start_container(1, name, data)


def track_process(kq, process_pid):
    try:
        kevent = select.kevent(
            process_pid,
            filter=select.KQ_FILTER_PROC,
            flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_ONESHOT,
            fflags=select.KQ_NOTE_EXIT
        )
        kq.control([kevent], 0)
        logger.info(f"Added {process_pid} for tracking")
    except Exception as e:
        logger.error(f'Failed to add process {process_pid} for monitoring')
        traceback.print_exception(type(e), e, e.__traceback__)


def remove_container(process_pid, notify=True):
    try:
        global JAIL_DICT
        jail = JAIL_DICT.get(process_pid)
        if not jail:
            return
        _, status = os.waitpid(process_pid, 0)
        exit_code = os.WEXITSTATUS(status)
        logger.info(f"[Parent] Child exited with code {exit_code}")
        logger.info(f"[Parent] Destroying jail with JID: {jail.jid}")
        jail.destroy_jail()
        JAIL_DICT.pop(process_pid)
        if notify==True:
            notity_status(jail.name, exit_code, f'Exited on: {datetime.now().isoformat()}')   
        logger.info(f'Container {jail.name} Stopped Succesfully') 
    except Exception as e:
        logger.error(f'Failed to remove {process_pid} jail')
        traceback.print_exception(type(e), e, e.__traceback__)


def clean_all_jails(kq):
    global JAIL_DICT

    for pid in JAIL_DICT.keys():
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    
    while len(JAIL_DICT.keys()):
        events = kq.control(None, 1)

        for ev in events:
            if ev.filter == select.KQ_FILTER_PROC:
                if ev.fflags & select.KQ_NOTE_EXIT:
                    logger.info(f"Process {ev.ident} exited during shutdown")
                    remove_container(ev.ident, notify=False)

    logger.info("All containers cleaned up")
    return


def run(sock_fd):
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)

    sock = socket.socket(fileno=sock_fd)
    # sock.setblocking(False)

    kq = select.kqueue()

    event = select.kevent(
        sock.fileno(),
        filter=select.KQ_FILTER_READ,
        flags=select.KQ_EV_ADD
    )

    kq.control([event], 0)

    buffer = b""

    logger.info("Child worker started")

    try:
        while True:
            events = kq.control(None, 1)

            for ev in events:
                if ev.filter == select.KQ_FILTER_PROC:
                    if ev.fflags & select.KQ_NOTE_EXIT:
                        logger.info(f"Process {ev.ident} exited")
                        remove_container(ev.ident)
                        break
                
                data = sock.recv(4096)

                if not data:
                    logger.info("Parent closed socket")
                    clean_all_jails(kq)
                    return

                buffer += data

                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    msg = line.decode()

                    name = msg.strip()
                    logger.info(f"Received container:{name}")

                    cont_pid = process_container(name)
                    if cont_pid and cont_pid!=-1:
                        track_process(kq, cont_pid)
                        

    finally:
        print("Child cleanup")
        sock.close()
        print('Closing Kqueue ...')
        kq.close()
        print('Parent Worker completed.')
        

