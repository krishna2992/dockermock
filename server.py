import os
import signal
import socket
import traceback
from flask import Flask, jsonify, request, abort
from threading import Lock
from app2.lib import set_ip_address
from app2.JailManager_ import JailManager, STATE, NET_TYPE
from app2.dns import SubnetTrie, DnsTree, run_dns
import kqueue_parent 

import atexit
app = Flask(__name__)
subnetTrie = SubnetTrie()
dnsTree = DnsTree()
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True  # enable indent

manager = JailManager()

parent_sock, child_sock = socket.socketpair()
child_pid = None


def handle_sigterm(signum, frame):
    print("SIGTERM received. Shutting down gracefully...")
    raise KeyboardInterrupt

signal.signal(signal.SIGTERM, handle_sigterm)
signal.signal(signal.SIGINT, handle_sigterm)
lock = Lock()


def mark_all_exited():
    try:
        # rows = manager.cursor.execute("select name from containers where status='running'").fetchall()
        # for row in rows:
        #     try:
        #         status = manager.stop_jail(row[0])
        #     except Exception  as e:
        #         print(e)

        manager.cursor.execute("update containers set status='exited' where status='running'")
    except Exception as e:
        print('Failed to mark all jails completed')
        print(e)


def shutdown():
    print("Signaling Child Process to Exit")
    print('Closing Parent socket')
    parent_sock.close()
    mark_all_exited()
    global child_pid
    if child_pid:
        print(f'Waiting on child {child_pid}')
        try:
            _, status = os.waitpid(child_pid, 0)
            exit_code = os.WEXITSTATUS(status)
            print(f"[Server] KqueueParent exited with code {exit_code}")
        except Exception as e:
            print(f'Failed to wait on kqueue_parent')
            traceback.print_exception(type(e), e, e.__traceback__)

    


def handle_close():
    shutdown()
    print('Closing Manager')
    manager.close()
    print('Exiting')


def create_lo0_addr():
    print('Setting Up DNS Server...')
    set_ip_address("lo0", "127.0.0.11", "255.255.255.255", broadcast_addr=None, sock=None)

@app.route('/api/container', methods=['GET'])
def list_containers():
    running = bool(request.args.get('running', False))
    with lock:
        containers = manager.list(running=running)
        return jsonify(containers)


@app.route('/api/container/<string:name>', methods=['GET'])
def get_container_json(name):
    with lock:
        container = manager.get_container(name)
        if container is None:
            return jsonify({"error": "Container not found"}), 404
        return jsonify(container)


@app.route('/api/container/<string:name>/status', methods=['GET'])
def get_container_status(name):
    with lock:
        status = manager.status_jail(name)
        if status is None:
            return jsonify({"error": "Container not found"}), 404
        return jsonify({"container": name, "status": status})


@app.route('/api/container/<string:name>/start', methods=['POST'])
def start_container(name):
    with lock:
        status = manager.start_jail(name)
        return jsonify({"container": name, "status": status})


@app.route('/api/container/<string:name>/stop', methods=['POST'])
def stop_container(name):
    with lock:
        status = manager.stop_jail(name)
        return jsonify({"container": name, "status": status})

@app.route('/api/container/<string:name>/exit_code', methods=['POST'])
def record_container(name):
    data = request.get_json()
    with lock:
        status = manager.update_exit_code(name, data['exit_code'])
        return jsonify({"container": name, "status": status})


@app.route("/dns", methods=["POST"])
def add_dns():
    data = request.get_json()
    domain = data.get("domain")
    ip = data.get("ip")
    network = data.get('network')
    if not domain or not ip or not network:
        return jsonify({"error": "Missing domain or ip or network"}), 400
    dnsTree.insert(domain+'.'+network, ip)
    return jsonify({"message": f"Added {domain+'.'+network} -> {ip}"}), 201


@app.route("/subnet", methods=["POST"])
def add_subnet():
    data = request.get_json()
    network = data.get("network")
    subnet  = data.get("subnet")
    if not network or not subnet:
        return jsonify({"error": "Missing domain or ip or network"}), 400
    subnetTrie.insert(network, subnet)
    return jsonify({"message": f"Added {network} -> {subnet}"}), 201


@app.route("/api/networks", methods=['POST'])
def add_network():
    data = request.get_json()
    name = data.get("name")
    prefix = data.get('prefix') or 24
    subnet = data.get('subnet')
    network_name, msg = manager.create_network(name, prefix=prefix, subnet=subnet)
    if not network_name:
        return jsonify({'error':msg}), 400
    return jsonify({"name": network_name, "subnet":msg}), 201

@app.route("/api/networks", methods=['GET'])
def get_networks():
    with lock:
        networks = manager.get_networks()
        return jsonify(networks), 200

@app.route("/api/images", methods=['GET'])
def get_images():
    with lock:
        images = manager.list_images()
        return jsonify(images), 200
    return {"error":"error"}, 500

@app.route("/api/images/<string:name>", methods=['GET'])
def get_image(name):
    with lock:
        img, err = manager.get_image(name)
        if err:
            return jsonify({'error':err}), 400
        return jsonify(img), 200

@app.route("/api/networks/<network>", methods=['DELETE'])
def delete_network(network):
    # with lock:
        # 
    pass


# @app.route("/network", methods=['POST'])
# def add_network():
#     data = request.get_json()
#     name = data.get("name")
#     prefix = data.get('prefix') or 24
#     network_name, msg = manager.create_network(name, prefix=prefix)
#     if not network_name:
#         return jsonify({'error':msg}), 400
#     return jsonify({"name": network_name, "subnet":msg}), 201

@app.route("/api/networks/<string:name>/start", methods=['POST'])
def start_network(name):
    with lock:
        ip, error = manager.start_network(name)
        if error:
            return jsonify({'error':error}), 400
        dnsTree.insert('host.jail.internal'+'.'+name, ip)
        return jsonify({'name':name}), 201

    
@app.route("/api/containers", methods=['POST'])
def create_container():
    data = request.get_json()
    with lock:
        res, container = manager.create_container(**data)
        if res != 0:
            return jsonify({'error':container}), 400
        return jsonify(container), 201




@app.route(f"/api/ports", methods=['POST'])
def add_ports():
    data = request.get_json()
    with lock:
        res, error = manager.add_rdr_ports(data)
        if res:
            return jsonify({'error':error}), 400
        return jsonify({}), 201

    
@app.route(f"/api/volumes", methods=['GET'])
def list_volumes():
    with lock:
        res = manager.get_volumes()
        return jsonify(res), 200

@app.route(f"/api/volumes", methods=['POST'])
def create_volume():
    data = request.get_json()
    print(data)
    if 'name' not in data:
        return {"error":"Volume Name is required"}, 400    
    with lock:
        res, err = manager.create_volume(data['name'])
        if not res:
            return jsonify({"error": err}), 400
        return jsonify(res), 201

@app.route('/api/container/<string:name>/delete', methods=['DELETE'])
def remove_container(name):
    with lock:
        err = manager.remove_container(name)
        if err:
            return jsonify({"error": err}), 400
        return "", 204


@app.route('/api/networks/<string:network>/attach', methods=['POST'])
def attach_network(network):
    data = request.get_json()
    if not 'name' in data:
        return jsonify({'error':"name cannot be null"}), 400
    with lock:
        err = manager.attach_network(data['name'], network)
        if err:
            return jsonify({"error": err}), 400
        return "", 201


atexit.register(handle_close)

if __name__ == '__main__':
    create_lo0_addr()
    manager.load_modules()
    manager.set_sysctls()
    run_dns("127.0.0.11", subnetTrie, dnsTree)

    child_pid = os.fork()

    if child_pid == 0:
        parent_sock.close()
        kqueue_parent.run(child_sock.fileno())
        print('Child Completed')
        os._exit(0)

    else:
        child_sock.close()
        manager.set_worker(parent_sock)
        app.run(debug=False, port=5000)
    