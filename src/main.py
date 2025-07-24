#!/usr/bin/env python3
import asyncio
import sys
import argparse
from .core.scanner import NetworkScanner

async def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Network Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.main example.com
  python -m src.main 192.168.1.1 -p top1000 -t connect,syn
  python -m src.main 10.0.0.0/24 --discover
  python -m src.main target.com -p 1-1000 -t connect,udp,os --threads 200
        """
    )
    parser.add_argument("target", help="Target IP, hostname, or network (CIDR)")
    parser.add_argument("-p", "--ports", default="common", 
                       help="Port range: 'common', 'top1000', '1-1000', or '80,443,8080'")
    parser.add_argument("-t", "--scan-types", default="connect",
                       help="Scan types: connect,syn,udp,os (comma-separated)")
    parser.add_argument("--threads", type=int, default=100,
                       help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=int, default=3,
                       help="Connection timeout in seconds (default: 3)")
    parser.add_argument("--discover", action="store_true",
                       help="Discover live hosts on network")
    parser.add_argument("-o", "--output", help="Output filename")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")
    parser.add_argument("--no-summary", action="store_true",
                       help="Don't print scan summary")
    
    args = parser.parse_args()
    scanner = NetworkScanner(threads=args.threads, timeout=args.timeout, verbose=args.verbose)
    
    if args.discover:
        print(f"Discovering hosts on {args.target}...")
        hosts = scanner.host_discovery.discover_hosts(args.target)
        if hosts:
            print(f"Found {len(hosts)} live hosts:")
            for host in hosts:
                print(f"  {host}")
        else:
            print("No live hosts found or discovery failed")
        return

    try:
        results = await scanner.comprehensive_scan(args.target, args.ports, args.scan_types.split(","))
        if "error" in results:
            print(f"Scan failed: {results['error']}")
            return
        filename = scanner.result_handler.save_results(results, args.output)
        if not args.no_summary:
            scanner.result_handler.print_summary(results)
        print(f"\nDetailed results saved to: {filename}")
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    except Exception as e:
        print(f"Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(main())