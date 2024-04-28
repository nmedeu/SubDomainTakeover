import whois
import requests
import socket


def check_whois(ip):
    """Check Whois information for a list of IP addresses."""
    try:
        w = whois.whois(ip)
        if w:
            return True
        else:
            return False
    except Exception as e:
        print(f"Error retrieving Whois for {ip}: {e}")
        return False
    

def check_web_server(ip):
    """Check if a web server responds at each IP address."""
    for protocol in ['http://', 'https://']:
        url = f"{protocol}{ip}"
        try:
            response = requests.get(url, timeout=5)
            #print(f"Response from {url}: {response.status_code}")
            if response:
                return True
        except requests.ConnectionError:
            print(f"Failed to connect to {url}")
        except requests.Timeout:
            print(f"Timeout when connecting to {url}")
        except requests.RequestException as e:
            print(f"Error during request to {url}: {e}")
    return False


def read_ports_from_file(file_path):
    ports = []
    with open(file_path, 'r') as file:
        for line in file:
            port = line.strip()
            if port.isdigit():
                ports.append(int(port))
    return ports


def scan_common_ports(ip):
    common_ports = read_ports_from_file('subguardian/subdomain_check/ports.txt')
    open_ports = []
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # Reduce timeout to speed up the scan
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except socket.error:
            pass
    return open_ports


def a_check(a_record):
    vulnerabilities = {}
    vulnerability_reason = []
    for a_record in a_record:

        # Check web server
        is_web = check_web_server(a_record['address'])

        # If not web server, further check
        if not is_web:

            # Common port scan
            open_ports = scan_common_ports(a_record['address'])
            
            if not open_ports:
                vulnerability_reason.append("Potentially Vulnerable (No open common ports)")

            # Whois check
            w = check_whois(a_record['name'])
            
            if not w:
                vulnerability_reason.append("Potentially Vulnerable (Whois check failed)")
            
        if vulnerability_reason:
            vulnerabilities[a_record['name']] = vulnerability_reason

    
    return vulnerabilities


