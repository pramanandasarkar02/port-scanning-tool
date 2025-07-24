from typing import Dict, Any
try:
    from scapy.all import IP, TCP, sr1
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

    def fingerprint(self, ip: str) -> Dict[str, Any]:
        if not SCAPY_AVAILABLE:
            return {"os": "Unknown", "confidence": 0.0, "method": "unavailable"}
        try:
            pkt = IP(dst=ip)/TCP(dport=80, flags="S")
            resp = sr1(pkt, timeout=self.timeout, verbose=0)
            if resp and resp.haslayer(IP):
                ttl = resp[IP].ttl
                window_size = resp[TCP].window if resp.haslayer(TCP) else None
                os_info = self.OS_SIGNATURES.get(ttl, {"os": "Unknown", "confidence": 0.1})
                return {
                    "os": os_info["os"],
                    "confidence": os_info["confidence"],
                    "ttl": ttl,
                    "window_size": window_size,
                    "method": "tcp_fingerprint"
                }
            return {"os": "Unknown", "confidence": 0.0, "method": "tcp_fingerprint"}
        except Exception as e:
            if self.verbose:
                print(f"OS fingerprinting error for {ip}: {e}")
            return {"os": "Unknown", "confidence": 0.0, "method": "error"}