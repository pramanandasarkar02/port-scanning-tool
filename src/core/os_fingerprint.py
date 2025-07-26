from typing import Dict, Any
import socket
import subprocess
import platform
import re

try:
    from scapy.all import IP, TCP, ICMP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class OSFingerprint:
    def __init__(self, timeout: int, verbose: bool):
        self.timeout = timeout
        self.verbose = verbose
        self.OS_SIGNATURES = {
            64: {"os": "Linux/Unix", "confidence": 0.7},
            128: {"os": "Windows", "confidence": 0.7},
            255: {"os": "Cisco/Solaris", "confidence": 0.6},
            32: {"os": "Windows 95/98", "confidence": 0.5},
            60: {"os": "Mac OS", "confidence": 0.6},
            254: {"os": "OpenBSD", "confidence": 0.7}
        }

    def _ping_ttl_detection(self, ip: str) -> Dict[str, Any]:
        """Use system ping to detect TTL for OS fingerprinting"""
        try:
            system = platform.system().lower()
            
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", str(self.timeout * 1000), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(self.timeout), ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout + 2)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Extract TTL from ping output
                ttl_match = re.search(r'ttl=(\d+)', output.lower())
                if not ttl_match:
                    ttl_match = re.search(r'TTL=(\d+)', output)
                
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    
                    if self.verbose:
                        print(f"Ping TTL detected: {ttl}")
                    
                    # Match against signatures
                    for known_ttl, info in self.OS_SIGNATURES.items():
                        if abs(known_ttl - ttl) <= 10:
                            return {
                                "os": info["os"],
                                "confidence": info["confidence"] * 0.8,  # Lower confidence for ping
                                "ttl": ttl,
                                "method": "ping_ttl"
                            }
                    
                    # If no exact match, make educated guess based on common TTL values
                    if 60 <= ttl <= 68:
                        return {"os": "Linux/Unix/macOS", "confidence": 0.6, "ttl": ttl, "method": "ping_ttl"}
                    elif 120 <= ttl <= 135:
                        return {"os": "Windows", "confidence": 0.65, "ttl": ttl, "method": "ping_ttl"}
                    elif ttl >= 240:
                        return {"os": "Network Device/Cisco", "confidence": 0.5, "ttl": ttl, "method": "ping_ttl"}
                        
        except Exception as e:
            if self.verbose:
                print(f"Ping TTL detection error: {e}")
        
        return None

    def _tcp_connect_fingerprint(self, ip: str) -> Dict[str, Any]:
        """TCP connect-based fingerprinting using standard sockets"""
        # Common port patterns for different OS
        windows_ports = [135, 139, 445, 3389]
        linux_ports = [22, 25, 53, 80]
        
        windows_open = 0
        linux_open = 0
        
        for port in windows_ports + linux_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:  # Port is open
                    if port in windows_ports:
                        windows_open += 1
                    if port in linux_ports:
                        linux_open += 1
                        
            except Exception:
                continue
        
        if windows_open > linux_open and windows_open > 0:
            return {"os": "Windows", "confidence": 0.7, "method": "port_pattern", "windows_ports": windows_open}
        elif linux_open > windows_open and linux_open > 0:
            return {"os": "Linux/Unix", "confidence": 0.7, "method": "port_pattern", "linux_ports": linux_open}
        elif windows_open > 0 or linux_open > 0:
            return {"os": "Unknown Server", "confidence": 0.4, "method": "port_pattern"}
            
        return None

    def _scapy_fingerprint(self, ip: str) -> Dict[str, Any]:
        """Original scapy-based fingerprinting with improvements"""
        if not SCAPY_AVAILABLE:
            return None
            
        ports_to_try = [80, 443, 22, 21, 25, 53, 135, 139, 445]
        
        for port in ports_to_try:
            try:
                # Try TCP SYN
                pkt = IP(dst=ip)/TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=self.timeout, verbose=0)
                
                if resp and resp.haslayer(IP):
                    ttl = resp[IP].ttl
                    window_size = resp[TCP].window if resp.haslayer(TCP) else None
                    
                    if self.verbose:
                        print(f"Scapy response on port {port}: TTL={ttl}, Window={window_size}")
                    
                    matched_os = {"os": "Unknown", "confidence": 0.0}
                    for known_ttl, info in self.OS_SIGNATURES.items():
                        if abs(known_ttl - ttl) <= 10:
                            matched_os = info
                            break
                    
                    if matched_os["confidence"] > 0:
                        return {
                            "os": matched_os["os"],
                            "confidence": matched_os["confidence"],
                            "ttl": ttl,
                            "window_size": window_size,
                            "method": "scapy_tcp",
                            "port": port
                        }
                        
            except Exception as e:
                if self.verbose:
                    print(f"Scapy error on port {port}: {e}")
                continue
        
        # Try ICMP if TCP failed
        try:
            pkt = IP(dst=ip)/ICMP()
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if resp and resp.haslayer(IP):
                ttl = resp[IP].ttl
                
                for known_ttl, info in self.OS_SIGNATURES.items():
                    if abs(known_ttl - ttl) <= 10:
                        return {
                            "os": info["os"],
                            "confidence": info["confidence"] * 0.9,
                            "ttl": ttl,
                            "method": "scapy_icmp"
                        }
                        
        except Exception as e:
            if self.verbose:
                print(f"ICMP fingerprinting error: {e}")
        
        return None

    def fingerprint(self, ip: str) -> Dict[str, Any]:
        """Main fingerprinting method with multiple fallback approaches"""
        if self.verbose:
            print(f"Starting OS fingerprinting for {ip}")
        
        results = []
        
        # Method 1: Scapy-based (if available and privileged)
        if SCAPY_AVAILABLE:
            scapy_result = self._scapy_fingerprint(ip)
            if scapy_result and scapy_result.get("confidence", 0) > 0:
                results.append(scapy_result)
                if self.verbose:
                    print(f"Scapy result: {scapy_result['os']} ({scapy_result['confidence']*100:.1f}%)")
        
        # Method 2: Ping TTL detection (always available)
        ping_result = self._ping_ttl_detection(ip)
        if ping_result and ping_result.get("confidence", 0) > 0:
            results.append(ping_result)
            if self.verbose:
                print(f"Ping result: {ping_result['os']} ({ping_result['confidence']*100:.1f}%)")
        
        # Method 3: TCP connect port pattern analysis
        tcp_result = self._tcp_connect_fingerprint(ip)
        if tcp_result and tcp_result.get("confidence", 0) > 0:
            results.append(tcp_result)
            if self.verbose:
                print(f"TCP pattern result: {tcp_result['os']} ({tcp_result['confidence']*100:.1f}%)")
        
        # Choose best result
        if results:
            best_result = max(results, key=lambda x: x.get("confidence", 0))
            
            # Add metadata about other methods tried
            best_result["alternative_detections"] = len(results) - 1
            
            if self.verbose:
                print(f"Best result: {best_result['os']} ({best_result['confidence']*100:.1f}%)")
            
            return best_result
        
        # If all methods failed, return unknown but with method info
        if self.verbose:
            print("All OS fingerprinting methods failed")
            
        return {
            "os": "Unknown", 
            "confidence": 0.0, 
            "method": "all_failed",
            "scapy_available": SCAPY_AVAILABLE,
            "methods_tried": ["scapy", "ping", "tcp_connect"]
        }