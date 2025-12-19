import subprocess
import json
import os
import sys
import enum
import signal
import sqlite3
import subprocess
import ipaddress
from time import sleep
from enum import Enum
from .Jail_ import Jail, get_jail_id_by_name
from .wrappers import rfork_wrapper
from .helpers import *
import ctypes
from app2.dns import SubnetTrie, DnsTree
from app2.network import *
from app2.zfs import clone_dataset, get_dataset
from app2.pf.pf import pfctl_table_add_addrs_list, pfctl_append_rdr_rule_generic, pfctl_table_del_addrs, pfctl_table_del_addr_list, pfctl_remove_rdr_port_rule
import uuid

CONTAINER_ROOT = 'zroot/jails/containers'
IMAGE_ROOT = 'zroot/jails/images'
CONF_ROOT = './conf'

VOLUME_MOUNT_ROOT = '/jails/volumes'
CONTAINER_MOUNT_ROOT = '/jails/containers' 


class STATE(Enum):
    CREATED = 0
    STARTED = 1
    RUNNING = 2
    STOPPED = 3
    EXITED  = 4
    FAILED  = 5
    STOPPING = 6

class NET_TYPE(Enum):
    HOST = 0
    VNET = 1

RFNAMEG		= (1<<0)	# UNIMPL new plan9 `name space' */
RFENVG		= (1<<1)	# UNIMPL copy plan9 `env space' */
RFFDG		= (1<<2)	# copy fd table */
RFNOTEG		= (1<<3)	# UNIMPL create new plan9 `note group' */
RFPROC		= (1<<4)	# change child = (else changes curproc) */
RFMEM		= (1<<5)	# share `address space' */
RFNOWAIT	= (1<<6)	# give child to init */
RFCNAMEG	= (1<<10)	# UNIMPL zero plan9 `name space' */
RFCENVG		= (1<<11)	# UNIMPL zero plan9 `env space' */
RFCFDG		= (1<<12)	# close all fds, zero fd table */
RFTHREAD	= (1<<13)	# enable kernel thread support */
RFSIGSHARE	= (1<<14)	# share signal handlers */
RFLINUXTHPN	= (1<<16)	# do linux clone exit parent notification */
RFSTOPPED	= (1<<17)	# leave child in a stopped state */
RFHIGHPID	= (1<<18)	# use a pid higher than 10 = (idleproc) */
RFTSIGZMB	= (1<<19)	# select signal for exit parent notification */
RFTSIGSHIFT	= 20	# selected signal number is in bits 20-27  */
RFTSIGMASK	= 0xFF
RFPROCDESC	= (1<<28)	
RFPPWAIT	= (1<<31)
RFSPAWN		= (1<<31)




class JailManager:
    def __init__(self, db='db/db.sqlite'):
        self.conn = sqlite3.connect(db, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.status = ['CREATED', 'STARTED', 'RUNNING', 'STOPPED', 'EXITED', 'FAILED', 'STOPPING']
        self.subnetallocator = SubnetAllocator()
    
    def update_exit_code(self, name, exit_code):
        self.cursor.execute('update containers set status=? where name =?', ('exited', name,))        
        self.conn.commit()
        return 'exited'

    def get_status_alpha(self, status):
        if status>=100:
            return 'FAILED'
        if status<len(self.status):
            print(status, self.status[status])
            return self.status[status]
        return 'UNKNOWN'

    def start_jail(self, name):
        res = self.cursor.execute('select ID, status from containers where name=?', (name,)).fetchone()
        if not res:
            return "NOJAIL"
        if res[1] == "started" or res[1] == "running":
            print('JAIL ALREADY: ', res[1])
            return res[1]
        
        
        pid = rfork_wrapper(RFPROC|RFNOWAIT|RFCFDG)
        if pid==0:
            os.execv(sys.executable, ['python', 'parent.py', name])
        print('pid:', pid)
        if pid<0:
            self.cursor.execute('update containers set status=? where ID=?', ("exited", res[0],))        
            self.conn.commit()
            return "FAILED: Failed to start parent"

        self.cursor.execute('update containers set status=? where ID=?', ("running", res[0],))
        self.conn.commit()
        # addresses = self.cursor.execute('select ip_address from container_networks where container_id = ?', (res[0],)).fetchall()
        # if addresses:
        #     addresses = [addr[0] for addr in addresses if addr]
        #     if addresses:
        #         try:
        #             pfctl_table_add_addrs_list("cni-nat", addresses, 0)
        #         except OSError as e:
        #             print(f'Failed to add {addresses} to table')
        return "started"

    def exists(self, name):
        res = self.cursor.execute('select ID from containers where name=?', (name, )).fetchone()
        if res:
            return True
        return False

    def status_jail(self, name):
        res = self.cursor.execute('select status from containers where name=?', (name, )).fetchone()
        if not res:
            return "DOESNOTEXIST"
        return res[0]

    def get_networks(self):
        rows = self.cursor.execute('select ID, name, driver from networks').fetchall()
        if not rows:
            return []
        columns = [col[0] for col in self.cursor.description]
        return [dict(zip(columns, row)) for row in rows]
    
    def get_volumes(self):
        rows = self.cursor.execute('select ID, name, driver, created_at from volumes').fetchall()
        if not rows:
            return []
        columns = [col[0] for col in self.cursor.description]
        return [dict(zip(columns, row)) for row in rows]

    def get_container_networks(self, cid):
        rows = self.cursor.execute('''
            SELECT 
                n.name  as name, 
                n.subnet as subnet, 
                n.prefix as prefix,
                n.driver as driver, 
                cn.ip_address as ip 
            from 
                networks n JOIN container_networks cn 
            on 
                cn.network_id = n.id 
            where 
                cn.container_id = ?;
        ''', (cid,)).fetchall()
        columns = [col[0] for col in self.cursor.description]
        networks = [dict(zip(columns, row)) for row in rows]
        return networks

    def get_container(self, name):
        row = self.cursor.execute('select * from containers where name= ?', (name,)).fetchone()
        if not row:
            return None
        columns = [col[0] for col in self.cursor.description]
        cont = dict(zip(columns, row))
        
        config = cont.pop('config_json')
        cont = cont | json.loads(config)
        cont['path'] = os.path.join(CONTAINER_MOUNT_ROOT, name) 
        cont['networks'] = self.get_container_networks(cont['id'])
        return cont

        


    def stop_jail(self, name):
        res = self.cursor.execute('select ID, status, config_json from containers where name=?', (name,)).fetchone()
        if not res:
            return 'DOESNOTEXIST' 
        if res[1] != "started" and res[1] != "running":
            print(f'Container {name} is not running')
            return res[1]
        
        jail_root = os.path.join(CONTAINER_MOUNT_ROOT, name)
        if not jail_root:
            print("jail_root not found\nRemoving jail manually", file=sys.stderr)
            subprocess.run(['jail', '-r', name])
        else:
            pid_path = os.path.join(jail_root, "jail.pid")
            print("jail_pid", pid_path)
            if not os.path.exists(pid_path):
                print("jail_pid not found\nRemoving jail manually", file=sys.stderr)
                subprocess.run(['jail', '-r', name])

            with open(pid_path, 'r+') as f:
                f.seek(0)
                try:
                    pid = int(f.readline())
                    print(f"Got pid for jail: {pid}\nKilling {pid}")
                    os.kill(pid, signal.SIGTERM)                    
                    # subprocess.run(['pkill', "-j", name])
                except ValueError as e:
                    print("Invalid pid:{e}\nRemoving jail manually", )
                    subprocess.run(['jail', '-r', name])
                finally:
                    f.seek(0)
                    f.truncate()
        removed = False
        for i in range(10):
            if jail_get_id(name) != CENOJAIL:
                sleep(1)
            else:
                removed = True
                break
        
        
        try:
            if not removed:
                print("Calling jail_remove")
                res = remove_jail_from_name(name)
        except JailDoesNotExist as e:
            print(e)
        # addresses = self.cursor.execute('select ip_address from container_networks where container_id = ?', (res[0],)).fetchall()
        # if addresses:
        #     addresses = [addr[0] for addr in addresses if addr]
        #     if addresses:
        #         try:
        #             pfctl_table_del_addr_list("cni-nat", addresses, 0)
        #         except OSError as e:
        #             print(f'Failed to remove {addresses} to table')
        ports = json.loads(res[2]).get('ports', [])
        network_rows = self.cursor.execute('''
            SELECT n.name
            FROM networks n
                JOIN container_networks cn
                ON n.id = cn.network_id
            WHERE cn.container_id = 23
        ''').fetchall()
        networks = [net[0] for net in network_rows if net]
        try:
            for port in ports:
                proto = socket.IPPROTO_UDP if port.get('proto')=='udp' else socket.IPPROTO_TCP
                for net in networks:
                    pfctl_remove_rdr_port_rule(f'cni-rdr/{net}', port['host'], proto)
        except Exception as e:
            print(e)
            
        return "exited"

    
    def list(self, running=True):
        try:
            if running:
                self.cursor.execute('select id, name, status from containers where status=?', ("running",))
            else:
                self.cursor.execute('select id, name, status from containers')

            columns  = [col[0] for col in self.cursor.description]
            data= [dict(zip(columns, row)) for row in self.cursor.fetchall()]
            return data
            
        except sqlite3.DatabaseError as e:
            print(e)
            return None
        # except Exception as e:
        #     print(e)
        #     return None
        raise Exception("Should not be executed")
    
    def create(self, name, path, net_type, descr=None, ip=None):
        self.cursor.execute('select id from containers where name=?', (name,))
        row = self.cursor.fetchone()
        if row:
            return -1, f'Container with name: {name} already exist'

        try:
            self.cursor.execute('insert into jails (name, path, type, description, status, ip) values (?, ?, ?, ?, ?, ?)', 
                                                    (name, path, net_type, descr, STATE.CREATED.value, ip,))
            
            self.conn.commit()
            print(self.cursor.fetchall())
        except sqlite3.DatabaseError:
            pass

    
    def _get_allocated_networks(self):
        """Return list of ipaddress.IPv4Network objects from DB."""
        self.cursor.execute("SELECT subnet, prefix FROM allocated_subnets")
        rows = self.cursor.fetchall()
        print(rows)
        return [ipaddress.ip_network(f"{subnet}/{prefix}") for subnet, prefix in rows]        

    def add_network(self, name, subnet, **kwargs):
        pass
    
    def setup_network_default_dns(self, network):
        pass

    def start_network(self, name):
        if name == 'host':
            return name, None
        row = self.cursor.execute('select ID, name, driver, subnet, prefix from networks where name = ?', (name,)).fetchone()
        if not row:
            return None, f"{name!r} doesn't exist"
        columns = [col[0] for col in self.cursor.description]
        network = dict(zip(columns, row))
        prefix = network.get('prefix')
        ip_net = ipaddress.ip_network(network.get('subnet')+'/'+str(prefix))
        ip_interface = ipaddress.ip_interface(f'{next(ip_net.hosts()).compressed}/{prefix}')
        if (check_interface_exist(name)):
            return str(ip_interface.ip), None
        
        try:
            print(f'Adding Address {network.get("subnet")+"/"+str(prefix)} to table')
            pfctl_table_add_addrs_list('cni-nat', [network.get('subnet')+'/'+str(prefix)], 0)
        except Exception as e:
            print('Failed to start network') 
            print(e)
            return "", f"Failed to start network: {name}"           
        try:
            if_name = create_interface("bridge")
            rename_interface(if_name, name)    
            set_interface_group(name, "jailnet")
            set_ip_address(name, str(ip_interface.ip), str(ip_interface.network.netmask), broadcast_addr=None)
            print(f"src: {network.get('subnet')}/{prefix}\n Dst: {str(ip_interface.ip)}\n")
            pfctl_append_rdr_rule_generic(
                name, 
                f'cni-rdr/{name}', 
                f"{network.get('subnet')}/{prefix}", 
                str(ip_interface.ip), 
                ['127.0.0.11/32'], 
                53, 
                dst_port=53, 
                af=socket.IPPROTO_UDP,
                quick=1
            )
            
        except OSError as e:
            return None, f"Failed to create network {name!r}: {e.strerror}"
        return str(ip_interface.ip), None

    def is_valid_subnet(self, subnet):
        try:
            return ipaddress.ip_network(subnet)
        except Exception as e:
            return None
        return None

    

    def create_network(self, name, **kwargs):
        self.cursor.execute('select ID from networks where name = ?', (name, ))
        rows = self.cursor.fetchall()
        
        if len(rows)>0:
            return None, f'{name!r} already exists'

        subnet = kwargs.get('subnet')
        
        if subnet:
            parsed_net = self.is_valid_subnet(subnet)
            if not parsed_net:
                return None, "Invalid Subnet"
            gateway = kwargs.get('gateway')
            if not gateway:
                gateway = str(next(parsed_net.hosts()))
            subnet, prefix = str(parsed_net.network_address), parsed_net.prefixlen
        else:
            subnet, prefix = self.subnetallocator.allocate_subnet(self._get_allocated_networks())
        print(name, subnet, prefix)
        if not subnet:
            return None, 'No Empty Network'
        try:
            self.cursor.execute(
                "INSERT INTO allocated_subnets (subnet, prefix) VALUES (?, ?)",
                (subnet, prefix)
            )

            self.cursor.execute(
                "INSERT into networks (name, subnet, prefix) VALUES (?, ?, ?)",
                (name, subnet, prefix)
            )
            self.conn.commit()
            print(f"Allocated subnet: {subnet+'/'+str(prefix)}")
            return name, subnet+'/'+str(prefix)
        except sqlite3.IntegrityError as e:
            print(e)
            print(f"Subnet {subnet} is already allocated.")
            return None, 'Failed to create network'
        return None, 'Error'



    def validate_container_options(self, networks: list, mounts: list):
        errors = []
        res = {}
        # --- Validate Networks ---
        if networks:
            placeholders = ",".join("?" for _ in networks)
            query = f"SELECT ID, name FROM networks WHERE name IN ({placeholders})"
            rows = self.cursor.execute(query, networks).fetchall()
            found = set(row[1] for row in rows)
            res['networks'] = [row[0] for row in rows]
            missing_networks = set(networks) - found
            if missing_networks:
                errors.append(f"Missing networks: {', '.join(missing_networks)}")

        # --- Validate Volume Mounts ---
        # print(mounts)
        volume_mounts = [m for m, v in mounts.items() if v["type"] == "volume"]
        if volume_mounts:
            placeholders = ",".join("?" for _ in volume_mounts)
            query = f"SELECT ID, name FROM volumes WHERE name IN ({placeholders})"
            rows = self.cursor.execute(query, volume_mounts).fetchall()
            found = set(row[1] for row in rows)
            res['volumes'] = [row[0] for row in rows]
            missing_volumes = set(volume_mounts) - found
            if missing_volumes:
                errors.append(f"Missing volumes: {', '.join(missing_volumes)}")

        return errors, res

    def create_path(self, paths_list, path_str):
        """
        Replaces occurrences of $PATH in `path_str` with a colon-separated string of the paths in `paths_list`.

        Args:
            paths_list (list of str): List of paths to join.
            path_str (str): Input string that may contain "$PATH".

        Returns:
            str: The modified string with "$PATH" replaced.
        """
        joined_paths = ':'.join(paths_list)
        return path_str.replace('$PATH', joined_paths)
        
    
    def handle_container_mounts(self, image_volumes, user_mounts):
        mounts = {}
        for m, v in image_volumes.items():
            mount = {
                "type":     "volume",
                "source":   str(uuid.uuid4()),
                "target":   m,
                "readonly": v.get('readonly', False)
            }
            mounts[m] = mount

        for m, v in user_mounts.items():
            mount = {
                "type": v['type'],
                "source":v['source'],
                "target": m,
                "readonly": user_mounts[m].get('readonly', False)
            }
            mounts[m] = mount

    
        sorted_keys = sorted(mounts, reverse=True)
        return [mounts[key] for key in sorted_keys]

    def create_anamous_volumes(self, mounts):
        
        for mount in mounts:
            if mount['type'] != 'volume':
                continue
            
            try:
                uuid.UUID(mount["source"])
            except ValueError:
                continue
            
            
            volume_name = mount["source"]
            volume_path = os.path.join(VOLUME_ROOT, volume_name)

            os.makedirs(volume_path, exist_ok=True)

            self.cursor.execute("""
                INSERT OR IGNORE INTO volumes (name, driver, path)
                VALUES (?, 'local', ?)
            """, (volume_name, volume_path))

            created_volumes.append((volume_name, volume_path))

        

    def create_container_json(self, image_json, **data):
        container = {}
        container['command'] = data.get('command') or image_json.get('command')
        container['entrypoint'] = data.get('entrypoint') or image_json.get('entrypoint')
        img_path = image_json.get('PATH', [])
        env_var = image_json.get('env', {})
        if 'env' in data:
            for key, value in data['env'].items():
                env_var[key] = value
        
        container['env'] = env_var
        if 'PATH' in data:
            container['env']['PATH'] = self.create_path(img_path, data.get('PATH'))
        else:
            container['env']['PATH'] = ':'.join(img_path)
        
        
        user = data.get('user') or image_json.get('user')
        if user:
            container['user'] = user
        
        workingDir = data.get('workingDir') or image_json.get('workingDir')
        if workingDir:
            container['workingDir'] = workingDir
        
        final_mounts = self.handle_container_mounts(image_json.get('volumes'), data.get('mounts'))
        self.create_anamous_volumes(final_mounts)
        container['mounts'] = final_mounts    
        container['ports'] = data.get('ports', [])
        return container

    def get_free_ip_for_network(self, network_id):
        rows = self.cursor.execute('select ip_address from container_networks where network_id = ?', (network_id,)).fetchall()
        used_ips = set(row[0] for row in rows)
        def allocate_ip(subnet_cidr):
            subnet = ipaddress.ip_network(subnet_cidr)
            cidr_prefix = subnet.prefixlen
            host_iter = subnet.hosts()
            try:
                next(host_iter)  # Skip the first usable IP
            except StopIteration:
                return None

            for ip in host_iter:  # excludes network and broadcast addresses and xxx.xxx.xxx.1
                if str(ip) not in used_ips:
                    return ip
            return None
        row = self.cursor.execute('select subnet, prefix from networks where id = ?', (network_id,)).fetchone()
        return allocate_ip(f'{row[0]}/{row[1]}')

    def create_dataset(self, image, name, snapshot_name='v1'):
        image_path = os.path.join(IMAGE_ROOT, image)
        image_dataset = get_dataset(image_path)
        if not image_dataset:
            return -1, f'No Data for image: {image!r}'
        container_dataset = os.path.join(CONTAINER_ROOT, name)
        res = clone_dataset(image_dataset, snapshot_name, container_dataset, mountpoint=os.path.join(CONTAINER_MOUNT_ROOT, os.path.join(name, 'root')))
        if res:
            return -1, 'Error creating dataset'
        return 0, None
    
    def link_container_volumes(self, mounts, cid):
        for mount in mounts:
            if mount['type'] != 'volume':
                continue
            source = mount['source']
            os.makedirs(os.path.join(VOLUME_MOUNT_ROOT, source), exist_ok=True)
            self.cursor.execute('INSERT OR IGNORE INTO volumes (name, driver, path) values (?, ?, ?)', (source, 'local', source))
            row = self.cursor.execute('SELECT id from volumes where name=?', (source,)).fetchone()
            print(row)
            self.cursor.execute('INSERT into volume_containers (volume_id, container_id) values (?, ?)', (row[0], cid,))

        

    def create_container(self, **data):
        name = data.get('name')
        image = data.get('image')
        networks = data.get('networks', [])
        mounts = data.get('mounts', [])
        env = data.get('env', {})
        command = data.get('command', [])
        entrypoint = data.get('entrypoint', [])
        ports = data.get('ports', [])
        user = data.get('user', None)
        if not name:
            return -1, f'Name cannot be empty'
        image_name, tag = image.split(':')
        errors = None
        res = {}
        if networks:
            errors, res = self.validate_container_options(networks, mounts)

        if errors:
            return -1, '\n'.join(errors)
        
        image_row = self.cursor.execute('select id, json_data from images where name=? and tag=?', (image_name, tag,)).fetchone()
        if not image_row:
            return -1, f'Invalid image: {image}'
        imgId, img_json = image_row[0], json.loads(image_row[1])

        cont_json = self.create_container_json(img_json, 
            env=env, 
            command=command, 
            entrypoint=entrypoint, 
            user=user, 
            workingDir=data.get('working_dir'),
            networks=networks, 
            mounts=mounts,
            ports=ports
        )
        cont_json['restart'] = data.get('restart', 'no')
        cont_json['rm']      = data.get('rm', False)
        cid = self.insert_container(name, imgId, cont_json)
        # result, msg = self.create_dataset(image, name, snapshot_name='base')
        # if result:
        #     self.conn.rollback()
        #     print('Changes rolled back')
        #     return -1, 'Failed to create container'

        if 'networks' in res and res['networks']:
            rows = []
            for network_id in res['networks']:
                placeholders = ",".join("?" for _ in res['networks'])
                addr = self.get_free_ip_for_network(network_id)
                rows.append((network_id, cid, str(addr),))
            query = "INSERT INTO container_networks (network_id, container_id, ip_address) values (?, ?, ?)"
            self.cursor.executemany(query, rows)
        self.link_container_volumes(cont_json['mounts'], cid)
        result, msg = self.create_dataset(image, name, snapshot_name='base')
        if result:
            self.conn.rollback()
            print('Changes rolled back', msg)
            return -1, 'Failed to create container'

        self.conn.commit()        
        return 0, {'id': cid}
        
    def insert_container(self, name, imag_id, config_json):
        self.cursor.execute('INSERT INTO containers (name, image_id, config_json) values (?, ?, ?)', (name, imag_id, json.dumps(config_json,)))
        inserted_id = self.cursor.lastrowid
        print("Inserted ID:", inserted_id)
        # Commit and close connection
        return inserted_id
    
    def close(self):
        self.cursor.close()
        self.conn.close()

    def add_rdr_ports(self, data):
        if not data:
            return 0
        network = data.get('network')
        if not network:
            return -1, 'Network cannot be null'
        for port in data.get('ports', []):
            host = port['host']
            container = port['container']
            rdr = port['rdr']
            if isinstance(rdr, str):
                rdr = [rdr]
            
            proto = socket.IPPROTO_UDP if port.get('proto')=='udp' else socket.IPPROTO_TCP
            pfctl_append_rdr_rule_generic(
                f'!{network}',
                f'cni-rdr/{network}',
                '0.0.0.0/0.0.0.0', 
                '(self)', 
                rdr, 
                container, 
                dst_port=host, 
                af=proto,
                quick=1 
            )
            
        return 0, ''
        

    def list_images(self):
        rows = self.cursor.execute("SELECT ID, name, tag, created_at from images").fetchall()
        columns = [col[0] for col in self.cursor.description ]
        return [dict(zip(columns, row)) for row in rows ]        

    def create_volume(self, name):
        row = self.cursor.execute('SELECT ID from volumes where name=?', (name,)).fetchone()
        if row:
            return None, 'Volume already exist'
        try:
            self.cursor.execute("INSERT INTO volumes(name, driver, path) VALUES (?, 'nullfs', ?)", (name, os.path.join(VOLUME_MOUNT_ROOT, name)))
            os.makedirs(os.path.join(VOLUME_MOUNT_ROOT, name), exist_ok=True)
            self.conn.commit()
            row = self.cursor.execute('SELECT ID, name from volumes where name=?', (name,)).fetchone()
            return {"ID":row[0], "name":row[1]}, None
        except sqlite3.IntegrityError as e:
            print(e)
            return None, f"Failed to create volumes: {e}"
        except Exception as e:
            print(e)
            return None, f"Failed to create volumes: {e}"
        return None, 'Error'
