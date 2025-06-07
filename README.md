A Multi-threaded Port Scanner
A fast, informative, multi-threaded Python port scanner for identifying open ports and potential vulnerabilities based on commonly targeted services.

Features
Accelerated Scanning: Multi-threaded design for rapid port checks.

Flexible Targets: Scans both IP addresses and domain names.

Clear Progress: Includes a user-friendly progress bar.

Port Identification: Lists all detected open ports.

Vulnerability Tagging: Flags ports with commonly vulnerable services.

Customizable: Adjustable port ranges and thread count via command-line arguments.

Graceful Exit: Supports interruption with Ctrl+C.

Getting Started
Set up the project locally with these steps.

Prerequisites
Requires Python 3 and pip.

Installation
Clone the repository:

git clone https://github.com/YourUsername/your-repo-name.git
cd your-repo-name

(Update GitHub details).

Create & Activate Virtual Environment (Recommended):

python3 -m venv venv

Linux/macOS: source venv/bin/activate

Windows (CMD): venv\Scripts\activate.bat

Windows (PowerShell): .\venv\Scripts\Activate.ps1

Install Dependencies:
Install tqdm via pip:

pip install tqdm

Alternatively, for project installation: pip install .

Usage
Run from the terminal within your activated virtual environment:

python port_scanner.py <target> [options]

Replace <target> with the IP or domain to scan.

Arguments:
<target>: Required. IP (e.g., 192.168.1.1) or domain (e.g., example.com).

-s, --start <PORT>: Starting port (default: 1).

-e, --end <PORT>: Ending port (default: 10000).

-t, --threads <NUMBER>: Concurrent threads (default: 100).

Examples:
Localhost scan: python port_scanner.py 127.0.0.1

Domain web ports: python port_scanner.py scanme.nmap.org --start 80 --end 443

Custom threads: python port_scanner.py 192.168.1.10 -t 50

Full range: python port_scanner.py my-server.example.com -s 1 -e 65535

Understanding the Output
Output shows port status, service, and vulnerability tag:

OPEN | Service Name | POTENTIALLY VULNERABLE (Description): Open port with a historically vulnerable service; requires further investigation.

OPEN | Unknown Service | Open (Service Not in Common Vulnerable List): Open port; service unknown or not commonly vulnerable.

CLOSED: Port is not open.

ERROR: Error during scan.

Important Note on "Vulnerable": The 'POTENTIALLY VULNERABLE' tag indicates a common service, not a confirmed flaw. True vulnerability depends on the software version and configuration. Always conduct deeper security assessments.

