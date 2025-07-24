import asyncio
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any, Optional
try:
    from scapy.all import IP, TCP, UDP, ICMP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class PortScanner:
    def __init__(self, threads: int, timeout: int, verbose: bool):
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 27017]
        self.TOP_1000_PORTS = list(range(1, 1001))
        self.SERVICE_SIGNATURES = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
            110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
            995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            6379: "Redis", 27017: "MongoDB"
        }

    def parse_ports(self, port_range: str) -> List[int]:
        if port_range == "common":
            return self.COMMON_PORTS
        elif port_range == "top1000":
            return self.TOP_1000_PORTS
        elif "-" in port_range:
            start, end = map(int, port_range.split("-"))
            return list(range(start, end + 1))
        return [int(p) for p in port_range.split(",")]

    async def tcp_connect_scan(self, ip: str, port: int) -> Dict[str, Any]:
        try:
            future = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
            banner = await self.grab_banner(ip, port)
            writer.close()
            await writer.wait_closed()
            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": self.identify_service(port, banner),
                "banner": banner or "",
                "method": "connect"
            }
        except asyncio.TimeoutError:
            return {"port": port, "protocol": "tcp", "state": "filtered", "method": "connect"}
        except ConnectionRefusedError:
            return {"port": port, "protocol": "tcp", "state": "closed", "method": "connect"}
        except Exception as e:
            if self.verbose:
                print(f"Error scanning {ip}:{port} - {e}")
            return {"port": port, "protocol": "tcp", "state": "error", "method": "connect"}

    def syn_scan(self, ip: str, port: int) -> Dict[str, Any]:
        if not SCAPY_AVAILABLE:
            return {"port": port, "protocol": "tcp", "state": "unavailable", "method": "syn"}
        try:
            pkt = IP(dst=ip)/TCP(dport=port, flags="S")
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            if resp is None:
                return {"port": port, "protocol": "tcp", "state": "filtered", "method": "syn"}
            elif resp.haslayer(TCP):
                if resp[TCP].flags == 18:
                    rst_pkt = IP(dst=ip)/TCP(dport=port, flags="R")
                    sr1(rst_pkt, timeout=1, verbose=0)
                    return {"port": port, "protocol": "tcp", "state": "open", "method": "syn"}
                elif resp[TCP].flags == 4:
                    return {"port": port, "protocol": "tcp", "state": "closed", "method": "syn"}
            elif resp.haslayer(ICMP):
                return {"port": port, "protocol": "tcp", "state": "filtered", "method": "syn"}
            return {"port": port, "protocol": "tcp", "state": "unknown", "method": "syn"}
        except Exception as e:
            if self.verbose:
                print(f"SYN scan error for {ip}:{port} - {e}")
            return {"port": port, "protocol": "tcp", "state": "error", "method": "syn"}

    async def grab_banner(self, ip: str, port: int) -> Optional[str]:
        try:
            future = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(future, timeout=2)
            if port in (80, 8080):
                writer.write(b'HEAD / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
            elif port in (21, 22, 25):
                pass
            else:
                writer.write(b'\r\n')
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()
            return banner.decode('utf-8', errors='ignore').strip()
        except:
            return None

    def identify_service(self, port: int, banner: Optional[str] = None) -> str:
        service = self.SERVICE_SIGNATURES.get(port, f"unknown-{port}")
        if banner:
            banner_lower = banner.lower()
            for key, value in {"ssh": "SSH", "http": "HTTP", "ftp": "FTP", "smtp": "SMTP",
                             "mysql": "MySQL", "postgresql": "PostgreSQL"}.items():
                if key in banner_lower:
                    return value
        return service

    async def scan_ports(self, ip: str, ports: List[int], scan_type: str) -> List[Dict[str, Any]]:
        if scan_type == "connect":
            tasks = [self.tcp_connect_scan(ip, port) for port in ports]
            return await asyncio.gather(*tasks, return_exceptions=True)
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.syn_scan if scan_type == "syn" else self.udp_scan, ip, port) for port in ports]
            for future in futures:
                try:
                    results.append(future.result())
                except Exception as e:
                    results.append({"error": str(e)})
        return results