# Port Scanning with OS Information / Version

A project for computer security lab (CSE-406).

## Features

- **Port scanning**: Identify open ports on a target host.
- **OS fingerprinting**: Detect operating system of the target.
- **Service detection**: Identify services running on open ports.
- **Host discovery**: Find live hosts on a network.

## Installation and Setup

1. **Clone the repository**
   ```bash
   git clone 
   cd 
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run scans with different options as shown below.

1. **Basic Port Scan**

   Scan the default (common) ports on a target IP or hostname.

   ```bash
   python -m src.main example.com
   ```

2. **Scan Top 1000 Ports**

   Scan the top 1000 commonly used ports on a target.

   ```bash
   python -m src.main example.com -p top1000
   ```

3. **Scan Specific Port Range**

   Scan ports in a custom range (e.g., ports 1 to 1000).

   ```bash
   python -m src.main example.com -p 1-1000
   ```

4. **Scan Specific Ports**

   Scan specific ports provided as comma-separated list (e.g., ports 80, 443, and 8080).

   ```bash
   python -m src.main example.com -p 80,443,8080
   ```

5. **Multiple Scan Types**

   Specify one or multiple scan types (comma-separated). Supported scan types are:

   - `connect`: Perform a regular TCP connect scan.
   - `syn`: Perform a SYN scan (stealth scan).
   - `udp`: Scan UDP ports.
   - `os`: Perform OS fingerprinting to identify the target’s operating system.

   Example scanning with connect and syn scans:

   ```bash
   python -m src.main example.com -t connect,syn
   ```

6. **Full Comprehensive Scan**

   Scan a range of ports and multiple scan types, including OS detection:

   ```bash
   python -m src.main example.com -p 1-1000 -t connect,udp,os
   ```

7. **Host Discovery on a Network**

   Discover live hosts in a network range using the `--discover` flag. Target can be a network in CIDR notation like:

   ```bash
   python -m src.main 192.168.1.0/24 --discover
   ```

8. **Control Number of Threads**

   Adjust concurrent scanning threads for faster or slower scanning:

   ```bash
   python -m src.main example.com --threads 200
   ```

9. **Timeout Control**

   Set a custom connection timeout in seconds:

   ```bash
   python -m src.main example.com --timeout 5
   ```

10. **Save Results to a File**

    Output the scan results to a file (e.g., JSON) for later analysis or reporting:

    ```bash
    python -m src.main example.com -o scan_results.json
    ```

11. **Suppress Scan Summary Output**

    Run scans without printing the summary on the console:

    ```bash
    python -m src.main example.com --no-summary
    ```

12. **Verbose Output**

    Enable verbose logging and debugging information during the scan:

    ```bash
    python -m src.main example.com -v
    ```

### Summary Table of Command Line Options and Their Uses

| Option              | Use Case / Description                                      | Example                                           |
|---------------------|------------------------------------------------------------|--------------------------------------------------|
| `target`            | Specify IP, hostname, or network CIDR                       | `example.com` or `192.168.1.0/24`                |
| `-p`, `--ports`     | Ports or port range to scan                                 | `-p top1000`, `-p 1-1000`, `-p 80,443,8080`      |
| `-t`, `--scan-types`| Types of scans to perform (connect, syn, udp, os)          | `-t connect,syn`                                  |
| `--threads`         | Number of concurrent threads                                | `--threads 200`                                   |
| `--timeout`         | Connection timeout in seconds                               | `--timeout 5`                                     |
| `--discover`        | Discover live hosts in a network without port scanning     | `192.168.1.0/24 --discover`                        |
| `-o`, `--output`    | Save scan results to a file                                 | `-o results.json`                                 |
| `-v`, `--verbose`   | Enable detailed logging                                     | `-v`                                              |
| `--no-summary`      | Do not print the scan summary at the end                   | `--no-summary`                                    |

# targeted Websites:
- scanme.nmap.org
- testphp.vulnweb.com
- vulnweb.com