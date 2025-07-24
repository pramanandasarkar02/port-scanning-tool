import socket
from typing import Optional

class TargetValidator:
    def validate_target(self, target: str) -> Optional[str]:
        import ipaddress
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            try:
                ip = socket.gethostbyname(target)
                print(f"Resolved {target} to {ip}")
                return ip
            except socket.gaierror as e:
                print(f"Failed to resolve {target}: {e}")
                return None