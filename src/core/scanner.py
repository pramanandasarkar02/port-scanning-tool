from typing import Dict, List, Any
from .port_scanner import PortScanner
from .host_discovery import HostDiscovery
from .os_fingerprint import OSFingerprint
from ..utils.validator import TargetValidator
from ..utils.logger import setup_logger
from ..utils.results import ResultHandler
import asyncio
import time
from datetime import datetime

class NetworkScanner:
    def __init__(self, threads: int = 100, timeout: int = 3, verbose: bool = False):
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.logger = setup_logger(verbose)
        self.validator = TargetValidator()
        self.port_scanner = PortScanner(threads, timeout, verbose)
        self.host_discovery = HostDiscovery()
        self.os_fingerprint = OSFingerprint(timeout, verbose)
        self.result_handler = ResultHandler()

    async def comprehensive_scan(self, target: str, port_range: str, scan_types: List[str]) -> Dict[str, Any]:
        start_time = time.time()
        ip = self.validator.validate_target(target)
        if not ip:
            return {"error": "Invalid target"}

        capabilities = self.check_permissions()
        self.logger.info(f"Available capabilities: {capabilities}")

        ports = self.port_scanner.parse_ports(port_range)
        results = {
            "target": target,
            "ip": ip,
            "scan_start": datetime.now().isoformat(),
            "scan_types": scan_types,
            "capabilities": capabilities,
            "ports_scanned": len(ports),
            "results": {}
        }

        for scan_type in scan_types:
            if scan_type == "connect" or capabilities.get(f"{scan_type}_scan", False):
                self.logger.info(f"Running {scan_type} scan on {len(ports)} ports...")
                scan_results = await self.port_scanner.scan_ports(ip, ports, scan_type)
                results["results"][scan_type] = [r for r in scan_results if not isinstance(r, Exception)]

        if "os" in scan_types and capabilities.get("os_fingerprint", False):
            self.logger.info("Performing OS fingerprinting...")
            results["os_fingerprint"] = self.os_fingerprint.fingerprint(ip)

        results["scan_duration"] = round(time.time() - start_time, 2)
        results["scan_end"] = datetime.now().isoformat()
        return results

    def check_permissions(self) -> Dict[str, bool]:
        capabilities = {
            "tcp_connect": True,
            "syn_scan": False,
            "udp_scan": False,
            "os_fingerprint": False
        }
        import os
        if os.name != 'nt' and os.geteuid() == 0:
            capabilities.update({"syn_scan": True, "udp_scan": True, "os_fingerprint": True})
        elif os.name == 'nt':
            capabilities.update({"syn_scan": True, "udp_scan": True, "os_fingerprint": True})
        return capabilities