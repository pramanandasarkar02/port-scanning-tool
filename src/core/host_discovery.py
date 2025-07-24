from typing import List
try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class HostDiscovery:
    def discover_hosts(self, network: str) -> List[str]:
        if not SCAPY_AVAILABLE:
            print("Host discovery requires Scapy")
            return []
        import ipaddress
        live_hosts = []
        try:
            net = ipaddress.ip_network(network, strict=False)
            if net.is_private:
                arp_pkt = ARP(pdst=str(net))
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                responses = srp(broadcast/arp_pkt, timeout=2, verbose=0)[0]
                for sent, received in responses:
                    live_hosts.append(received.psrc)
            else:
                for ip in list(net.hosts())[:50]:
                    pkt = IP(dst=str(ip))/ICMP()
                    resp = sr1(pkt, timeout=1, verbose=0)
                    if resp:
                        live_hosts.append(str(ip))
        except Exception as e:
            print(f"Host discovery error: {e}")
        return live_hosts