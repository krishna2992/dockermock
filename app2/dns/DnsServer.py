import argparse
import time, os
from dnslib.server import DNSServer, BaseResolver, DNSLogger
import dns.resolver
import socket
import json
import ipaddress
import subprocess
from dnslib import DNSRecord, RR, QTYPE, A  # Make sure this import is at top
from .SubnetTrie import SubnetTrie
from .DnsTree import DnsTree


system_resolvers = dns.resolver.get_default_resolver().nameservers

class DynamicResolver(BaseResolver):
    def __init__(self, trie, dnstree):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(2)
        self.trie = trie
        self.dnstree = dnstree

    def add_network(self, name, subnet):
        self.trie.insert(name, ipaddress.IPv4Network(subnet))

    def resolve(self, request, handler):
        client_ip = handler.client_address[0]
        qname = str(request.q.qname).lower()
        qtype = QTYPE[request.q.qtype]
        reply = request.reply()

        if qtype == "A":
            network_name = self.trie.find(client_ip)
            if network_name:
                host_ip = self.dnstree.collect_from(qname+network_name)
                if host_ip:
                    for ip in host_ip:
                        reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=300))
                    return reply
        
        for forwarder in system_resolvers:
            try:
                self.sock.sendto(request.pack(), (forwarder, 53))
                data, _ = self.sock.recvfrom(512)
                return DNSRecord.parse(data)
            except Exception as e:
                print(f"[DNS] Fallback to {forwarder} failed: {e}")

        return reply



def run_dns(bind_ip, subnetTrie, dnsTree, port=53):
    resolver = DynamicResolver(subnetTrie, dnsTree)
    # resolver.add_network("office",       "10.0.4.0/24")
    print(bind_ip, subnetTrie, dnsTree, port)
    logger = DNSLogger(log="", prefix=False)
    print(os.getpid())
    subprocess.run(['sockstat', '-4', '-p', '53'])
    server = DNSServer(resolver, address=bind_ip, port=port, logger=logger)
    server.start_thread()
    print(f"🚀 DNS server running on {bind_ip}:{port}")
    return server

