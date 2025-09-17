<h1 style="text-align:center;padding:0;"><img src="/logo.webp" style="display:inline-block;width:64px;height:64px;" alt="Proxy Port Scanner" /><span style="display:inline-block;vertical-align:top;line-height:64px;">Proxy Port Scanner</span></h1>

![License: MIT](https://img.shields.io/badge/license-MIT-green.svg) [![Contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/fredrik-stigsson/Proxy-Port-Scanner/issues) ![Version 1.0.0](https://img.shields.io/badge/version-1.0.0-blue)

An anonymous port scanner written in Python that uses a proxy server to hide the identity of the one performing the scan.

---

## Features

- Scan specified ports or ranges of ports on a target host.
- Use a proxy server to maintain anonymity.
- Support for multiple threads and customizable timeouts.

---

## Installation

```bash
git clone https://github.com/fredrik-stigsson/Proxy-Port-Scanner.git
cd Proxy-Port-Scanner
python3 -m venv .venv
. .venv/bin/activate (Linux)
.venv/Scripts/activate (Windows)
pip install -r requirements.txt
deactivate
```

---

## Example usage
```bash
python3 scanner.py --host example.com --proxy 127.0.0.1:9050
python3 scanner.py --host example.com --proxy 127.0.0.1:9050 --ports 1-1024
python3 scanner.py --host 192.168.1.10 --proxy 127.0.0.1:9050 --ports 22,80,8000-8100
python3 scanner.py --host 192.168.1.10 --proxy socks.example.net:1080 --ports 22,80,443 --threads 50 --timeout 3
```
