import threading
import logging
logger = logging.getLogger(__name__)
# import subprocess
# Define the DNS tree classes
class DnsTreeNode:
    def __init__(self):
        self.children = {}
        self.ip = None

class DnsTree:
    def __init__(self):
        self.root = DnsTreeNode()
        self.lock = threading.Lock()
        
    def rsplit_generator(self, domain):
        start = len(domain)
        while start:
            end = domain.rfind('.', 0, start)
            yield domain[end+1:start]
            if end == -1:
                break
            start = end

    def insert(self, domain, ip):
        logger.info(f"Adding {domain} -> {ip}")
        with self.lock:
            node = self.root
            for part in self.rsplit_generator(domain):
                if part not in node.children:
                    node.children[part] = DnsTreeNode()
                node = node.children[part]
            node.ip = ip
            # subprocess.run(["pfctl", "-t", "cni-nat", "-T", "add", str(ip)])


    def clear_ip(self, domain):
        logger.info(f"Adding {domain} -> {ip}")
        with self.lock:
            node = self.root
            for part in self.rsplit_generator(domain):
                if part not in node.children:
                    node.children[part] = DnsTreeNode()
                node = node.children[part]
            node.ip = None


    def collect_from(self, domain):
        node = self.root
        for part in self.rsplit_generator(domain):
            if part in node.children:
                node = node.children[part]
            else:
                return []  # No match, return empty list
        return self.collect_all(node)


    def longest_prefix_node(self, key_parts):
        node = self.root
        last_node_with_ip = None
        for part in key_parts:
            if part in node.children:
                node = node.children[part]
                if node.ip is not None:
                    last_node_with_ip = node
            else:
                break
        return last_node_with_ip

    def collect_all(self, node=None):
        if node is None:
            node = self.root
        ips = []
        if node.ip is not None:
            ips.append(node.ip)
        for child in node.children.values():
            ips.extend(self.collect_all(child))
        return ips

    def all(self):
        node = self.root



# # Instantiate DNS tree
# dns_tree = DnsTree()

# # Insert domains in reverse order: "com", "example", "www"
# dns_tree.insert("1.kafka", "192.0.2.1")
# dns_tree.insert("2.kafka", "192.0.2.4")
# dns_tree.insert("example.com", "192.0.2.2")
# dns_tree.insert("api.openai.com", "192.0.2.3")

# # Test longest prefix match
# query = "kafka"
# ips = dns_tree.collect_from(query)
# if ips:
#     print(f"IPs {ips}")
# else:
#     print("No match found.")

# # List all IPs in the tree
# all_ips = dns_tree.collect_from("example.com")
# print("All IPs in DNS Tree:", all_ips)
