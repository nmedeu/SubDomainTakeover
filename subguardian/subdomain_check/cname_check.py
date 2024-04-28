import dns.resolver
import requests
import json
import re
import os



def load_json_data(filepath):
    """Load JSON data from a file."""
    # Load data from files
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
            
            return data
    except Exception as e:
        
        return []

def load_error_patterns(filepath):
    """Load error patterns from a plain text file."""
    try:
        with open(filepath, 'r') as f:
            error_patterns = f.read().splitlines()
            
            return error_patterns
    except Exception as e:
        
        return []
    

def check_http_response_and_content(subdomain, service_fingerprints, error_patterns):
    
    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        

        # Fetch the content of the page
        page_content = response.text.lower()
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            cname = str(rdata.target)
            
        vulnerability_reason = []
        # Check each service for a matching CNAME pattern and fingerprint
        for service in service_fingerprints:
            for pattern in service['cname']:
                if re.search(pattern.replace('.', r'\.').replace('*', r'.*'), cname):
                    
                    if service['fingerprint'].lower() in page_content:
                        print(f"Fingerprint '{service['fingerprint']}' found for service '{service['service']}' in response for {subdomain}.")
                        vulnerability_reason.append(f"Fingerprint '{service['fingerprint']}' found for service '{service['service']}'")
                        

        # Check for error patterns regardless of service fingerprint
        for error in error_patterns:
            if error.lower() in page_content:
                vulnerability_reason.append(f"Error pattern '{error}' found")

        # Check specific HTTP status codes for general vulnerability indications
        if response.status_code in [404, 410]:
            print(f"HTTP {response.status_code} found, indicating a possible takeover opportunity for {subdomain}.")
            vulnerability_reason.append(f"HTTP {response.status_code} found, indicating a possible takeover opportunity")
            
        elif response.status_code == 403:
            vulnerability_reason.append(f"HTTP 403 found, indicating possible misconfiguration")
            print(f"{subdomain} returned HTTP 403, indicating possible misconfiguration.")

        if vulnerability_reason:
            return {subdomain: vulnerability_reason}
        else:
            return None
    except requests.RequestException as e:
        print(f"Failed to fetch webpage for {subdomain}: {e}")
    

def cname_check(entry):
    subdomains = [record['name'] for record in entry]
    """Analyze a list of subdomains for potential vulnerabilities using service fingerprints and error patterns."""
    service_fingerprints = load_json_data('subguardian/subdomain_check/fingerprints.json')
    error_patterns = load_error_patterns('subguardian/subdomain_check/errors.txt')
    vulnerable_subdomains = {}
    for subdomain in subdomains:
        vulnerability_reason = check_http_response_and_content(subdomain, service_fingerprints, error_patterns)
        if vulnerability_reason:
            vulnerable_subdomains.update(vulnerability_reason)
            print(f"Vulnerability confirmed for {subdomain}: {vulnerability_reason}")
        else:
            print(f"No vulnerabilities found for {subdomain}.")
    return vulnerable_subdomains


# Load data from files


vulnerable_subdomains = cname_check([{'name': 'www.bucrib.com', 'type': 'subdomain'}, {'name': 'blog.bucrib.com', 'type': 'subdomain'}, {'name': 'forms.bucrib.com', 'type': 'subdomain'}])
print("Vulnerable subdomains:", vulnerable_subdomains)
