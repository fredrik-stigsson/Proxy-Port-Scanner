#!/usr/bin/env python3
"""
Proxy Port Scanner

Version 1.0.0

Usage examples:
  python3 scanner.py --host example.com --proxy 127.0.0.1:9050
  python3 scanner.py --host example.com --proxy 127.0.0.1:9050 --ports 1-1024
  python3 scanner.py --host 192.168.1.10 --proxy 127.0.0.1:9050 --ports 22,80,8000-8100
  python3 scanner.py --host 192.168.1.10 --proxy socks.example.net:1080 --ports 22,80,443 --threads 50 --timeout 3

Notes:
 - Proxy format: host:port
 - Timeout is per-port connect timeout in seconds.
"""

import argparse
import socks
import socket
import concurrent.futures
import time
import sys
from typing import List, Tuple
import pycurl
import certifi
from io import BytesIO

# Parse ports in argument
def parse_ports(ports_str: str) -> List[int]:
    out = set()
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a = int(a.strip()); b = int(b.strip())
            if a > b:
                a, b = b, a
            out.update(range(a, b+1))
        else:
            out.add(int(part))
    return sorted(p for p in out if 0 <= p <= 65535)

# Parse proxy address, host:port
def parse_proxy(proxy_str: str) -> Tuple[str,int]:
    if ":" not in proxy_str:
        raise ValueError("Proxy must be in host:port format")
    host, port = proxy_str.rsplit(":", 1)
    return host, int(port)

# Get a banner
def get_banner(s: socks.socksocket, target_host: str, port: int, 
               proxy_host: str, proxy_port: int, proxy_user: str = None, 
               proxy_pass: str = None) -> str:
    
    # Variables
    banner = ""
    
    # Get http/https banner
    try:
        buffer = BytesIO()
        c = pycurl.Curl()
        c.setopt(c.URL, target_host + ":" + str(port))
        c.setopt(c.NOBODY, True)
        c.setopt(c.HEADERFUNCTION, buffer.write)
        c.setopt(c.TIMEOUT, 8)
        c.setopt(c.PROXY, proxy_host)
        c.setopt(c.PROXYPORT, proxy_port)
        c.setopt(c.PROXYTYPE, c.PROXYTYPE_SOCKS5_HOSTNAME)
        c.setopt(pycurl.PROXYUSERNAME, proxy_user)
        c.setopt(pycurl.PROXYPASSWORD, proxy_pass)
        c.setopt(c.HTTP09_ALLOWED, True)
        c.setopt(pycurl.SSL_VERIFYPEER, 1)
        c.setopt(pycurl.SSL_VERIFYHOST, 2)
        c.setopt(c.CAINFO, certifi.where())
        c.perform()
        c.close()
        return buffer.getvalue().decode("utf-8", errors="replace").strip()
    except Exception as ex:
        #print(f"{type(ex).__name__}: {ex}")
        pass

    # Get an ordinary banner
    try:
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
    except Exception as ex:
        #print(f"{type(ex).__name__}: {ex}")
        pass

    # Return banner
    return banner

# Attempt to connect to (target_host, port) via a SOCKS5 proxy
def scan_port_via_socks5(target_host: str, port: int,
                         proxy_host: str, proxy_port: int,
                         proxy_user: str = None, proxy_pass: str = None,
                         timeout: float = 3.0) -> Tuple[int, str, str]:

    # Create a soket, set proxy and timeout
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, proxy_host, proxy_port, False, username=proxy_user, password=proxy_pass)
    s.settimeout(timeout)
    try:
        s.connect((target_host, port))
        banner = get_banner(s, target_host, port, proxy_host, proxy_port)
        s.close()
        if banner != "":
            return port, "open", banner
        else:
            return port, "open", "----"
                
    except socket.timeout:
        return port, "filtered", "timeout"
    except ConnectionRefusedError:
        return port, "closed", "connection refused"
    except socks.ProxyError as pe:
        msg = str(pe).lower()
        if "connection refused" in msg:
            return port, "closed", "connection refused"
        elif "timed out" in msg: 
            return port, "filtered", "timeout"
        else:
            return port, "proxy-error", f"proxy error: {pe}"
    except Exception as ex:
        msg = f"{type(ex).__name__}: {ex}"
        return port, "filtered", msg
    finally:
        try:
            s.close()
        except Exception:
            pass

# Run scan
def run_scan(target_host: str, ports: List[int],
             proxy_host: str, proxy_port: int,
             proxy_user: str, proxy_pass: str,
             threads: int, timeout: float, delay_between_attempts: float):
    print(f"Scanning {target_host}, {len(ports)} ports via SOCKS5 proxy {proxy_host}:{proxy_port}")
    print(f"Threads={threads}, Timeout={timeout}s, DelayBetweenAttempts={delay_between_attempts}s\n")
    print("Open ports:")
    print("---------------------------------------------------")

    results = []
    start = time.time()

    def worker(p):
        if delay_between_attempts > 0:
            time.sleep(delay_between_attempts)
        return scan_port_via_socks5(target_host, p, proxy_host, proxy_port, proxy_user, proxy_pass, timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        future_to_port = {ex.submit(worker, p): p for p in ports}
        try:
            for fut in concurrent.futures.as_completed(future_to_port):
                port, status, detail = fut.result()
                results.append((port, status, detail))

                # Only print open ports
                if(status == "open"):
                    print(f"{port}, {status}, {detail}\n")
        except KeyboardInterrupt:
            print("\nUser interrupted scan. Shutting down...")
            ex.shutdown(wait=False)
            sys.exit(1)

    elapsed = time.time() - start
    print(f"\nScan complete in {elapsed:.2f}s. Summary:")
    print("---------------------------------------------------")
    opens = [p for p,s,_ in results if s == "open"]
    closed = [p for p,s,_ in results if s == "closed"]
    filtered = [p for p,s,_ in results if s == "filtered"]
    proxy_err = [p for p,s,_ in results if s == "proxy-error"]

    print(f"  Open:       {len(opens)} ports")
    print(f"  Closed:     {len(closed)} ports (connection refused)")
    print(f"  Filtered:   {len(filtered)} ports (timeouts/filtered)")
    print(f"  ProxyError: {len(proxy_err)} ports (proxy connection issues)")

    # Return full results for programmatic use
    return results

# Main entry point
def main():

    # Parse arguments
    parser = argparse.ArgumentParser(description="Proxy Port Scanner")
    parser.add_argument("--host", required=True, help="Target hostname or IP")
    parser.add_argument("--proxy", required=True, help="SOCKS5 proxy host:port (e.g. 127.0.0.1:9050)")
    parser.add_argument("--ports", default="7,21,22,23,25,53,80,81,110,111,113,135,139,143,179,199,389,443,445,465,514,587,631,993,995,1022,1024,1025,1026,1027,1028,1029,1110,1352,1353,1720,1723,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2011,2012,2013,2014,2015,2016,2017,2018,2019,2020,2021,2022,2023,2024,2025,2026,2027,2028,2029,2030,2031,2032,2033,2034,2049,3000,3306,4443,4444,5000,5009,5060,5061,5432,548,5631,5666,5900,5901,5902,6000,6001,8000,8080,8888,10000,49152,49153,51413,32768", help="Ports (e.g. 22,80,443 or 1-1024 or combined 22,80,8000-8100)")
    parser.add_argument("--proxy-user", default=None, help="Proxy username (optional)")
    parser.add_argument("--proxy-pass", default=None, help="Proxy password (optional)")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default 50)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Connect timeout in seconds (default 3.0)")
    parser.add_argument("--delay", type=float, default=1.0, help="Per-task small delay to throttle requests (seconds, default 0.0)")
    args = parser.parse_args()

    # Parse ports and proxy
    ports = parse_ports(args.ports)
    proxy_host, proxy_port = parse_proxy(args.proxy)

    # Start Proxy Port Scanner
    print("\nProxy Port Scanner")
    print("---------------------------------------------------")
    print("By running this tool you confirm you have permission to scan the target.")
    run_scan(args.host, ports, proxy_host, proxy_port, args.proxy_user, args.proxy_pass, args.threads, args.timeout, args.delay)

# Tell python to run main method
if __name__ == "__main__": 
    main()