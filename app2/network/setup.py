import ipaddress
from .SubnetAllocator import SubnetAllocator

def start_network(self, network):
    net_type = network.get('type')
    if net_type == 'vnet':
        net_if = network.get('net_if')
        net_addr = network.get('net_addr')
        if get_if_index(net_if) == -1:
            print(f"Interface {net_if} doesn't exist")
            print(f"Creating Interface {net_if} type {'bridge'!r}")

            name = create_interface('bridge')
            print(f'Created interface {name!r}')

            rename_interface(name, net_if)
            print(f'Rename: {name}--> {net_if}')

            ip_interface = ipaddress.ip_interface(net_addr)
            res = set_if_address(net_if, str(ip_interface.ip), str(ip_interface.network.netmask), brodcast_addr=None)


            



def create_network(name, conn, prefix=24):
    allocator = SubnetAllocator(conn)
    subnet = allocator.allocate_subnet(prefix)
    prefix = int(subnet.split('/')[1])
    



