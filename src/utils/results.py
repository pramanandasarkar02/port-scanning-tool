import json
from datetime import datetime
from typing import Dict, Any

class ResultHandler:
    def save_results(self, results: Dict[str, Any], filename: str = None) -> str:
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"logs/scan_results_{timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        return filename

    def print_summary(self, results: Dict[str, Any]):
        print(f"\n{'='*60}")
        print(f"SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Target: {results['target']} ({results['ip']})")
        print(f"Scan Duration: {results['scan_duration']} seconds")
        print(f"Ports Scanned: {results['ports_scanned']}")
        open_ports = []
        for scan_type, scan_results in results.get("results", {}).items():
            for port_result in scan_results:
                if port_result.get("state") == "open":
                    open_ports.append(f"{port_result['port']}/{port_result['protocol']}")
        print(f"Open Ports Found: {len(set(open_ports))}")
        if open_ports:
            print(f"\nOpen Ports:")
            for scan_type, scan_results in results.get("results", {}).items():
                open_in_scan = [r for r in scan_results if r.get("state") == "open"]
                if open_in_scan:
                    print(f"  {scan_type.upper()} Scan:")
                    for port_result in open_in_scan:
                        service = port_result.get("service", "unknown")
                        banner = port_result.get("banner", "")
                        banner_info = f" ({banner[:50]}...)" if banner else ""
                        print(f"    {port_result['port']}/{port_result['protocol']} - {service}{banner_info}")
        if "os_fingerprint" in results:
            os_info = results["os_fingerprint"]
            print(f"\nOS Fingerprinting:")
            print(f"  OS: {os_info.get('os', 'Unknown')}")
            print(f"  Confidence: {os_info.get('confidence', 0):.1%}")