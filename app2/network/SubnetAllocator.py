import ipaddress
import sqlite3

class SubnetAllocator:
    def __init__(self, base_network='10.0.0.0/16'):
        self.base_network = ipaddress.ip_network(base_network)
        

    # def _initialize_database(self):
    #     self.cursor.execute('''
    #         CREATE TABLE IF NOT EXISTS allocated_subnets (
    #             id INTEGER PRIMARY KEY AUTOINCREMENT,
    #             subnet TEXT NOT NULL,
    #             prefix INTEGER NOT NULL,
    #             UNIQUE(subnet, prefix)
    #         )
    #     ''')
    #     self.conn.commit()

    # def _get_allocated_networks(self):
    #     """Return list of ipaddress.IPv4Network objects from DB."""
    #     self.cursor.execute("SELECT subnet, prefix FROM allocated_subnets")
    #     rows = self.cursor.fetchall()
    #     return [ipaddress.ip_network(f"{subnet}/{prefix}") for subnet, prefix in rows]

    def _is_overlapping(self, candidate, allocated_networks):
        """Check if candidate subnet overlaps with any allocated one."""
        for net in allocated_networks:
            if candidate.overlaps(net):
                return True
        return False

    def find_available_subnet(self, prefix, allocated):
        """Find the first available subnet of given prefix in base network."""
        # allocated = self._get_allocated_networks()

        for candidate in self.base_network.subnets(new_prefix=prefix):
            if not self._is_overlapping(candidate, allocated):
                return candidate
        return None

    def allocate_subnet(self, allocated, prefix=24):
        """Find and allocate a new subnet with given prefix."""
        subnet = self.find_available_subnet(prefix, allocated)
        if subnet:
            return str(subnet.network_address), subnet.prefixlen
        print(f"No available /{prefix} subnet in {self.base_network}")
        return None

    # def list_allocated_subnets(self):
    #     """Return all allocated subnets as strings."""
    #     self.cursor.execute("SELECT subnet, prefix FROM allocated_subnets ORDER BY subnet")
    #     return [f"{subnet}/{prefix}" for subnet, prefix in self.cursor.fetchall()]

    


