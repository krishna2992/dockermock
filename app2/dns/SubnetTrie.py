import ipaddress
import random
import time
import sys

class TrieNode:
    def __init__(self):
        self.children = [None, None]
        self.network_name = None

class SubnetTrie:
    def __init__(self):
        self.root = TrieNode()
        self.node_count = 1  # root node

    def _get_bit(self, ip_int, bit_index):
        return (ip_int >> (31 - bit_index)) & 1

    def insert(self, network_name, subnet_str):
        node = self.root
        subnet = ipaddress.IPv4Network(subnet_str)
        ip_int = int(subnet.network_address)
        prefix_len = subnet.prefixlen

        for bit_index in range(prefix_len):
            bit = self._get_bit(ip_int, bit_index)
            if node.children[bit] is None:
                node.children[bit] = TrieNode()
                self.node_count += 1
            node = node.children[bit]
        node.network_name = network_name
    
    def estimate_memory(self):
        seen = set()

        def sizeof_node(node):
            if id(node) in seen or node is None:
                return 0
            seen.add(id(node))

            size = sys.getsizeof(node)
            size += sys.getsizeof(node.children)
            size += sys.getsizeof(node.network_name)
            for child in node.children:
                size += sizeof_node(child)
            return size

        return sizeof_node(self.root)



    def find(self, ip):
        node = self.root
        ip_int = int(ipaddress.IPv4Address(ip))
        last_found = None
        for bit_index in range(32):
            bit = self._get_bit(ip_int, bit_index)
            if node.children[bit] is None:
                break
            node = node.children[bit]
            if node.network_name is not None:
                last_found = node.network_name
        return last_found

# Setup
# trie = SubnetTrie()

# # Generate 10,000 subnets (e.g. 10.0.0.0/24, 10.0.1.0/24, ...)
# for i in range(10000):
#     subnet = f"10.{i // 256}.{i % 256}.0/24"
#     trie.insert(f"subnet-{i}", subnet)

# # Generate 10,000 random IPs for lookup
# random_ips = []
# for _ in range(10000):
#     ip = ipaddress.IPv4Address(random.randint(0, 2**32 - 1))
#     random_ips.append(ip)

# # Benchmark
# lookup_times = []
# found = 0

# for ip in random_ips:
#     start = time.perf_counter()
#     result = trie.find(ip)
#     end = time.perf_counter()
#     lookup_times.append((end - start) * 1_000_000)  # µs
#     if result:
#         found += 1

# # Stats
# avg = sum(lookup_times) / len(lookup_times)
# worst = max(lookup_times)
# best = min(lookup_times)

# print(f"🌲 Nodes created: {trie.node_count}")
# print(f"🔍 Total lookups: {len(lookup_times)}")
# print(f"✅ Matches found: {found}")
# print(f"⏱️ Average lookup time: {avg:.2f} µs")
# print(f"🚀 Fastest lookup: {best:.2f} µs")
# print(f"🐢 Slowest lookup: {worst:.2f} µs")


# trie = SubnetTrie()

# for i in range(10):
#     subnet = ipaddress.IPv4Network(f"192.168.{i}.0/24")
#     trie.insert(f"network-{i}", subnet)

# memory_used = trie.estimate_memory()

# print(f"🧠 Total nodes: {trie.node_count}")
# print(f"📦 Total memory: {memory_used / 1024:.2f} KB")
# print(f"📊 Average per subnet: {memory_used / 10:.2f} bytes")
