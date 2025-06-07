import socket
import argparse  # For command-line arguments
import threading # For concurrent scanning
from queue import Queue # For thread-safe port queue
from tqdm import tqdm # For progress bar
import ipaddress # For robust IP address validation

# --- Configuration ---
# This dictionary lists ports typically associated with services that have
# historically been common targets for vulnerabilities if left unpatched
# or misconfigured. This does NOT guarantee a port is vulnerable, but
# rather indicates a service that, if found open, warrants further investigation.
COMMON_VULNERABLE_SERVICE_PORTS = {
    21: "FTP (often insecure)",             # File Transfer Protocol - can be insecure (anonymous, plaintext)
    22: "SSH (brute-force target)",         # Secure Shell - target for brute-force if weak creds
    23: "Telnet (unencrypted)",             # Telnet - unencrypted communication, easily sniffed
    25: "SMTP (spam/spoofing risk)",        # Simple Mail Transfer Protocol - risk of open relay, spoofing
    53: "DNS (DDoS amplification)",         # Domain Name System - can be used for DDoS attacks
    69: "TFTP (no authentication)",         # Trivial File Transfer Protocol - no authentication
    80: "HTTP (web app vulns)",             # HyperText Transfer Protocol - web application vulnerabilities (SQLi, XSS)
    110: "POP3 (email client)",             # Post Office Protocol 3
    139: "NetBIOS (older SMB)",             # NetBIOS Session Service - often related to older, vulnerable SMB
    143: "IMAP (email client)",             # Internet Message Access Protocol
    443: "HTTPS (web app vulns)",            # HTTPS - web application vulnerabilities (SQLi, XSS)
    445: "SMB/CIFS (EternalBlue, etc.)",     # Server Message Block - critical if unpatched (e.g., WannaCry)
    3306: "MySQL (database target)",        # MySQL database - if exposed and unsecure
    3389: "RDP (remote access target)",     # Remote Desktop Protocol - target for brute-force, specific RDP vulns
    5900: "VNC (remote control)"            # Virtual Network Computing - often weak authentication
}

# --- Threading Configuration ---
# Default number of concurrent threads for the scanning.
# Adjust this value based on your network speed and target's capacity.
# Too many threads can overwhelm your network or the target.
DEFAULT_NUM_THREADS = 100
PORT_QUEUE = Queue() # A thread-safe queue to hold ports to be scanned
RESULTS_LOCK = threading.Lock() # Lock to protect shared data (OPEN_PORTS_INFO)
OPEN_PORTS_INFO = [] # List to store details of open/scanned ports

# --- Helper Functions ---
def get_service_banner(sock):
    """
    Attempts to grab a banner from an open port to identify the service.
    Sends a basic HTTP HEAD request as a first attempt.
    """
    try:
        # Try sending a common HTTP request to get a banner
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        # Receive up to 1024 bytes of response
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        if banner:
            return banner.splitlines()[0] # Return the first line of the banner
    except socket.timeout:
        pass # No banner received within the timeout
    except Exception:
        pass # Handle other potential errors (e.g., non-HTTP service)
    return None # Return None if no banner could be grabbed

def scan_port(target_ip, port):
    """
    Connects to a single port on the target IP and determines its status (OPEN/CLOSED).
    Also attempts to grab a service banner.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set a timeout for the socket connection and receive operations.
    # This is crucial for avoiding indefinite waits on filtered/closed ports.
    sock.settimeout(1.0) # Increased to 1 second for banner grabbing, can be adjusted

    status = "CLOSED" # Default status
    service_info = "Unknown Service" # Default service description
    vulnerability_tag = "No Common Vulnerability Identified" # Default vulnerability assessment

    try:
        # connect_ex is used as it returns an error indicator (0 for success)
        # instead of raising an exception on connection refusal.
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            status = "OPEN"
            
            # Check if the port is in our list of common vulnerable service ports
            if port in COMMON_VULNERABLE_SERVICE_PORTS:
                service_info = COMMON_VULNERABLE_SERVICE_PORTS[port]
                vulnerability_tag = f"POTENTIALLY VULNERABLE ({service_info})"
            else:
                vulnerability_tag = "Open (Service Not in Common Vulnerable List)"
            
            # Attempt to grab a service banner for more specific information
            banner = get_service_banner(sock)
            if banner:
                service_info = f"{service_info} (Banner: {banner})"
            
        # If connection fails, status remains "CLOSED", and vulnerability_tag remains default
    except socket.error as e:
        # Catch network-related errors (e.g., host unreachable)
        status = f"ERROR: {e}"
        vulnerability_tag = "N/A (Scan Error)"
    except Exception as e:
        # Catch any other unexpected exceptions
        status = f"ERROR: {e}"
        vulnerability_tag = "N/A (Script Error)"
    finally:
        sock.close() # Ensure the socket is always closed

    # Use a lock to safely append results to the shared list from multiple threads
    with RESULTS_LOCK:
        OPEN_PORTS_INFO.append({
            'port': port,
            'status': status,
            'service_info': service_info,
            'vulnerability_tag': vulnerability_tag
        })
    
    # Update the tqdm progress bar for the main thread
    # tqdm.current refers to the TQDM object created in the main function.
    if isinstance(tqdm.current, tqdm):
        tqdm.current.update(1)

def worker(target_ip):
    """
    Worker function for each thread. Continuously retrieves ports from the queue
    and calls scan_port until a sentinel value (None) is received.
    """
    while True:
        port = PORT_QUEUE.get() # Get a port from the queue
        if port is None: # Check for the sentinel value to exit the thread
            break
        scan_port(target_ip, port) # Scan the retrieved port
        PORT_QUEUE.task_done() # Mark the task as done for queue.join()

# --- Main Scan Function ---
def run_scan(target_input, start_port, end_port, num_threads):
    """
    Manages the multi-threaded port scanning process.

    Args:
        target_input (str): The IP address or domain name to scan.
        start_port (int): The starting port number for the scan.
        end_port (int): The ending port number for the scan.
        num_threads (int): The number of concurrent threads to use.
    """
    target_ip = ""
    try:
        target_ip = str(ipaddress.ip_address(target_input))
        print(f"Scanning IP address: {target_ip}")
    except ValueError:
        print(f"'{target_input}' is not a valid IP address. Attempting to resolve domain...")
        try:
            target_ip = socket.gethostbyname(target_input)
            print(f"Resolved '{target_input}' to IP: {target_ip}")
        except socket.gaierror:
            print(f"Error: Could not resolve domain '{target_input}'. Please check the name or provide a valid IP.")
            return # Exit if target cannot be resolved

    print(f"\nScanning {target_ip} from port {start_port} to {end_port} with {num_threads} threads...\n")

    # Create and start worker threads
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(target_ip,))
        thread.daemon = True # Allows the main program to exit even if threads are still running
        threads.append(thread)
        thread.start()

    # Populate the queue with ports to scan
    total_ports_to_scan = end_port - start_port + 1
    # Use tqdm to show overall progress. Set tqdm.current for updates from threads.
    with tqdm(total=total_ports_to_scan, desc="Scanning Ports") as pbar:
        tqdm.current = pbar # This makes the pbar object accessible to the worker threads for updates
        for port in range(start_port, end_port + 1):
            PORT_QUEUE.put(port) # Add each port to the queue

    # Wait for all tasks in the queue to be completed
    PORT_QUEUE.join()

    # Signal worker threads to exit by putting None (sentinel value) into the queue for each thread
    for _ in range(num_threads):
        PORT_QUEUE.put(None)
    # Wait for all worker threads to finish their execution
    for thread in threads:
        thread.join()

    print("\nScan completed.")

    # --- Summary and Reporting ---
    # Sort the results by port number for a clean, ordered output
    OPEN_PORTS_INFO.sort(key=lambda x: x['port'])

    found_open_ports = []
    potentially_vulnerable_open_ports_details = []

    # Print detailed info for each open port *after* the progress bar is complete
    for info in OPEN_PORTS_INFO:
        if info['status'] == "OPEN":
            found_open_ports.append(info['port'])
            # Check if the open port was flagged as potentially vulnerable
            if "POTENTIALLY VULNERABLE" in info['vulnerability_tag']:
                potentially_vulnerable_open_ports_details.append(info)
            
            # Print detailed status for each open port after the main scan loop
            print(f"Port {info['port']:<5}: {info['status']:<6} | {info['service_info']} | {info['vulnerability_tag']}")
        elif "ERROR" in info['status']:
            # You can uncomment this if you want to see errors for closed/filtered ports
            # during the summary as well.
            # print(f"Port {info['port']:<5}: {info['status']:<6} | {info['service_info']} | {info['vulnerability_tag']}")
            pass


    print(f"\n--- Scan Summary for {target_ip} ---")
    print(f"Total ports scanned: {total_ports_to_scan}")
    
    if found_open_ports:
        print(f"Open ports found: {found_open_ports}")
        
        if potentially_vulnerable_open_ports_details:
            print(f"\nOpen ports associated with commonly targeted/vulnerable services:")
            for detail in potentially_vulnerable_open_ports_details:
                print(f"  - Port {detail['port']}: {COMMON_VULNERABLE_SERVICE_PORTS.get(detail['port'], 'N/A')} ({detail['vulnerability_tag']})")
            print("\nNOTE: These ports host services that have historical vulnerabilities if misconfigured or unpatched.")
            print("      Further investigation (e.g., service version enumeration, exploit searching) is highly recommended.")
        else:
            print("\nNo open ports found that are commonly associated with historically vulnerable services.")
    else:
        print("No open ports found in the scanned range.")

    print("\nRemember: An open port is only 'vulnerable' if the service running on it has a specific security flaw.")
    print("This scanner provides an initial assessment based on known common service ports and basic banner grabbing.")


# --- Main Execution Block (for command-line arguments) ---
def main(): # Wrapped main execution into a function for setup.py entry_points
    parser = argparse.ArgumentParser(
        description="A multi-threaded Python port scanner with basic service identification.",
        formatter_class=argparse.RawTextHelpFormatter # Corrected typo here (lowercase 'r')
    )
    # Define command-line arguments for target, port range, and number of threads
    parser.add_argument("target", help="The IP address or domain name to scan (e.g., 192.168.1.1, example.com)")
    parser.add_argument("-s", "--start", type=int, default=1,
                        help="The starting port number for the scan (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=10000,
                        help="The ending port number for the scan (default: 10000)")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_NUM_THREADS,
                        help=f"Number of concurrent threads to use (default: {DEFAULT_NUM_THREADS})")

    args = parser.parse_args()

    # Basic input validation for port ranges
    if not (1 <= args.start <= 65535 and 1 <= args.end <= 65535 and args.start <= args.end):
        print("Error: Port numbers must be between 1 and 65535, and start port must be less than or equal to end port.")
    elif args.threads <= 0:
        print("Error: Number of threads must be a positive integer.")
    else:
        # Call the main scanning function with arguments from the command line
        run_scan(args.target, args.start, args.end, args.threads)

if __name__ == "__main__":
    main() # Call the main function when the script is run directly

