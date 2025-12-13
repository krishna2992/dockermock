
from ctypes.util import find_library
from time import sleep
from .helpers import *
import subprocess
import ctypes
import json
import pwd
import sys
import traceback
import os
import ipaddress


PATH_ENV = {"PATH":"/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin"}

ZFS_ROOT = 'zroot/jails/containers'

CONTROOT = '/jails/containers'

VOLUME_MOUNT_ROOT = '/jails/volumes'

class Jail:
    def __init__(self, iid, name, isvnet, json, config):
        self._id = iid
        self.name = name
        self.isvnet = isvnet
        self.jid = None
        self.net_if = config.get('net_if')
        self.json = json
        self.epair = []
        self.kwargs = config
        self.log= f'log/{name}.log'
        self.devfs_mounted = False
        
    
    def mount_devfs(self):
        if self.devfs_mounted:
            return 
        res = mount_jail_defvs(self.name, self.json.get("path"), self.json.get("devfs_ruleset", 4))
        if res!= CENOERR:
            print("ERROR: Failed to mount devfs")
        self.devfs_mounted = True

    def mount_tmpfs(self):
        res = mount_jail_tmpfs(self.name, self.json.get("path"))
        if res!= CENOERR:
            print("ERROR: Failed to mount tmpfs")

    def unmount_tmpfs(self):
        res = unmount_jail_tmpfs(self.json.get("path"))
        if res!= CENOERR:
            print("ERROR: Failed to unmount tmpfs")

    def unmount_devfs(self):
        if not self.devfs_mounted:
            return 
        res = unmount_jail_defvs(self.json.get("path"))
        if res!= CENOERR:
            print("ERROR: Failed to unmount devfs")
        self.devfs_mounted = False

    def handle_fs_umounts(self):
        fs_mounts = self.kwargs.get('fs_mounts', [])
        if not fs_mounts:
            return
        for fs in fs_mounts:
            if fs == 'devfs':
                self.unmount_devfs()
            elif fs == 'tmpfs':
                self.unmount_tmpfs()

    def handle_fs_mounts(self):
        fs_mounts = self.kwargs.get('fs_mounts', [])
        if not fs_mounts:
            return
        
        for fs in fs_mounts:
            if fs == 'devfs':
                self.mount_devfs()
            elif fs == 'tmpfs':
                self.mount_tmpfs()
        

    def create_jail(self)-> int:
        # print(self.json)

        self.jid = start_jail_from_json(self.json)
        # Handle Jail Networking Setup
        networks = self.kwargs.get('networks', None)
        if networks:
            if networks[0].get('driver') != 'host':
                for network in networks:
                    net_type = network.get('driver')
                    if net_type == 'bridge':
                        if self.create_epair_up(network) != CENOERR:
                            raise Exception("Failed to Create Epair")
            self.attach_inteface_up()

        # Handle Spacial Mounts
        self.handle_fs_mounts()
        # Handle User Defined Mounts
        self.handle_mounts()


    def create_epair_up(self, network):
        epair = create_epair()
        if not epair:
            return CERROR
        self.epair.append(epair)
        print(f'Created interface ({epair[:-1]}a, {epair[:-1]}b)')
        print(f"Adding {epair[:-1]+'b'} to host {network.get('name')}")
        try:            
            bridge_if(network.get('name'), epair[:-1]+'b', add=True)
        except OSError as e:
            print(f"Failed to add {epair[:-1]+'b'} to {network.get('name')}")
            return CERROR
        return CENOERR
        

    def handle_mounts(self):
        mounts = self.kwargs.get('mounts')
        if not mounts:
            return
        jail_root = self.json.get('path')
        for m in mounts:
            target = os.path.realpath(m['target'])   
            dest = os.path.join(jail_root , m['source'][1:])
            tpe =  m['type']
            if tpe == 'volume':
                target = os.path.join(VOLUME_MOUNT_ROOT, m['target'])
            

            if not os.path.exists(dest):
                os.makedirs(dest, exist_ok=True)
            flags = 0
            print(f'Mounting {target} on {dest}')
            if m['readonly'] == True:
                flags |= MNT_RDONLY
            mount_host_to_jail(dest, target, flags)


    def attach_epair(self):
        for epair in self.epair:
            res = attach_vnet_ifaces(self.name, epair)
            if res != 0:
                raise CustomException(f'Failed to attach epair:{epair}', self.name)
        return

        
    def redirect_io(self, stdin_path="/dev/null"):
        fd_out = os.open(self.log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        fd_in  = os.open(stdin_path, os.O_RDONLY)

        os.dup2(fd_in, 0)   
        os.dup2(fd_out, 1)     
        os.dup2(fd_out, 2)  
        os.close(fd_in)      
        os.close(fd_out)     

    def deattach_epair(self):
        if not self.epair:
            return 
        print("Deattching", self.epair)
        for epair in self.epair:
            res= deattach_vnet_ifaces(self.name, epair)
            if res!= CENOERR:
                print("Failed to deattach interface ", epair)
             
        return 
        
    def destroy_epair(self):
        if not self.epair:
            return
        for epair in self.epair:
            if(destroy_if(epair) != CENOERR):
                print("Failed to destroy", epair)
        self.epair = []
        return

    def jail_attach(self):
        if not self.name:
            raise Exception('JID is null.Failed to attach')
        return jail_attach(self.name)
        

    def switch_user(self):
        username = self.kwargs.get('user')
        if not username or username == 'root':
            return
        try:
            pw = pwd.getpwnam(username)
            os.setgid(pw.pw_gid)
            os.setuid(pw.pw_uid)
        except KeyError:
            raise CustomException(f"User '{username}' not found", self.name)
        except PermissionError as e:
            raise CustomException(f"Permission error: {e}", self.name)
        print(f'Succesfully switched to user {username}')
            

    def attach_inteface_up(self):
        if not self.epair:
            return
        if not self.jid:
            return
        for epair in self.epair:
            res = attach_vnet_ifaces(self.name, epair)
            if res!=CENOERR:
                print(f'Failed to attach interface to jail {self.name!r}: {epair}', file=sys.stderr)
        
        print(f'Succesfully Attached {self.epair}')
        
    def setup_network(self):
        '''Setup Jail Networking
        '''
        networks = self.kwargs.get('networks', None)
        if not  networks:
            return

        if networks[0]['driver'] == 'host':
            return
        
        nameservers = []

        for i, network in enumerate(networks):
            net_type = network.get("driver", None)
            if not net_type:
                continue
        
            if net_type == 'bridge':
                ip_interface = ipaddress.ip_interface(network.get('ip')+'/'+str(network.get('prefix')))
                res = set_if_address(self.epair[i], str(ip_interface.ip), str(ip_interface.network.netmask), brodcast_addr=None)
                if res!= CENOERR:
                    print(f"Failed to set ip address for {self.epair[i]}", file=sys.stderr)

                if 'subnet' in network and network['subnet']:
                    subnet_str = str(network['subnet'])+'/'+str(network['prefix'])
                    host = str(next(ipaddress.ip_network(subnet_str).hosts()))
                    nameservers.append(host)
                    print(f'Adding route {subnet_str} via {host}')
                    subprocess.run(['route', 'add', subnet_str, 'via',host])
        if nameservers:
            # Add default
            print('Adding default ')
            subprocess.run(['route', 'add', 'default', str(nameservers[0])])
            nstr = '# Generated by Jail\n'
            for ns in nameservers:
                nstr += f'nameserver {ns}\n'

            with open('/etc/resolv.conf', 'w+') as f:
                f.write(nstr)
        print("Setup Complete")


    def setup_jail(self):
        '''This code will be executed from inside jail. 
            This allow us to configure jail such as adding nameserver, hosts, setup epait, 
            mounts if any. Child process wil be executing this code. Do not use infinite loops
        '''
        res = subprocess.run(['/bin/sh', '/etc/rc'])
        self.setup_network()
        
        print("Setup Complete")

    def stop_jail(self):
        if not self.jid and not self.name:
            print('JID and Name both are null. Failed to stop jail')
            return 

        jid = str(self.jid or self.name)
        res = subprocess.run(['jexec', jid, '/bin/sh', '/etc/rc.shutdown'])
            
        res = remove_jail_from_name(self.name)
        # res = subprocess.run(['jail', '-r', jid])
        if res==-1:
            print(f'Failed to remove jail: {jid}')
        return 
        
    def handle_unmount(self):
        mounts = self.kwargs.get('mounts')
        if not mounts:
            return
        jail_root = self.json.get('path')
        for m in mounts:
            dest = os.path.join(jail_root , m['source'][1:])
            if unmount_jail_mounts(dest) != CENOERR:
                print(f'Failed to unmount {dest}')


    def destroy_jail(self):
        print(f'Stopping Jail {self.name}')
        try:
            self.deattach_epair()
            self.stop_jail()
            self.destroy_epair()
            self.handle_fs_umounts()
            self.handle_unmount()
        except Exception as e:
            print(e)

    def write_pid(self):
        path = self.kwargs.get('path')
        pid_file = os.path.join(path, 'jail.pid')
        with open(pid_file, 'w+') as f:
            print(os.getpid(), file=f)

    def child(self):
        self.redirect_io()
        self.write_pid()
        res =  self.jail_attach()
        if res!= 0:
            print(os.strerror(ctypes.get_errno()), file=sys.stderr)
            exit(CEATTERR)
        self.setup_jail()
        try:
            self.switch_user()
            entrypoint = self.kwargs.get('entrypoint')
            command = self.kwargs.get('command', [])
            first, args = None, []
            # Check if entrypoint exist
            if entrypoint:
                # Set entrypoint as entrypoint
                first = entrypoint
                # args[0] = entrpoint
                args.append(entrypoint)
            else:
                # If no entrpoint
                # command[0] = entrypoint
                if command and len(command)>0:
                    first = command[0]

            # Extend args with command
            args.extend(command)
            envs = self.kwargs.get('env', {})
            print('kwargs', self.kwargs.get('workingDir'))
            # if self.kwargs.get('kwargs'):
            os.chdir(self.kwargs.get('workingDir', '/'))
            print(os.listdir())
            os.execvpe(first, args=args, env=envs)
        except OSError as e:    
            traceback.print_exc()
            print(f"[Child] Exec failed: {e}", file=sys.stderr)
            sys.exit(128)
        except Exception as e:
            traceback.print_exc()
            sys.exit(1)