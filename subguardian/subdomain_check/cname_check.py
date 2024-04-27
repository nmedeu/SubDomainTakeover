import dns.resolver
import requests
from bs4 import BeautifulSoup
import re
import json
import os

try: 
    with open('/Users/nurassylmedeuov/Desktop/SubdomainTakevoer/SubDomainTakeover/subguardian/subdomain_check/fingerprints.json', 'r') as f:
        service_fingerprints = json.load(f)
        print("JSON loaded successfully. Number of services loaded:", len(service_fingerprints))
except Exception as e:
     print(f"Failed to load JSON: {e}")

def check_cname(subdomain):
    """Resolve the CNAME for a given subdomain."""
    """If DNS resolver fails to resolve a given subdomain, then DNS record does not exists -> no vulnearbility"""
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            print(f"{subdomain} is an alias for {rdata.target}.")
            return str(rdata.target)
    except dns.resolver.NoAnswer:
        print(f"No CNAME record found for {subdomain}.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    

def check_http_response(subdomain):
    """Check the HTTP response of the subdomain."""

    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        print(f"HTTP Status Code for {subdomain}: {response.status_code}")
        if response.status_code == 404 or response.status_code == 410:
            print("Possible takeover opportunity detected (HTTP 404/410)!")
            return True
        elif response.status_code == 200:
            print("Resource active (HTTP 200).")
        elif response.status_code == 403:
            print("Possible misconfiguration detected (HTTP 403).")
            return True
    except requests.ConnectionError:
        print(f"Failed to establish a connection to {subdomain}.")
    except requests.Timeout:
        print(f"Request to {subdomain} timed out.")
    except Exception as e:
        print(f"An error occurred: {e}")


    return False


def check_for_error_messages(subdomain):
    """Fetch webpage content and parse it for common error messages."""

    
    with open('errors.txt') as f:
        common_error_patterns = f.read().splitlines()
    
    try:
        # Attempt to fetch the webpage content
        response = requests.get(f"http://{subdomain}", timeout=5)
        content = response.content
    except requests.RequestException as e:
        print(f"Failed to fetch the webpage for {subdomain}: {e}")
        return False  # Unable to fetch the webpage
    
    # Parse the fetched content
    soup = BeautifulSoup(content, 'html.parser')
    page_text = soup.get_text().strip()
    print(page_text)
    # Look for common error patterns in the page text
    for error_pattern in common_error_patterns:
        if error_pattern.lower() in page_text.lower():
            print(f"Error message detected on page: {error_pattern}")
            return True  # Error message found
    return False  # No error message found

#print(check_for_error_messages('blog.bucrib.com'))


import dns.resolver

def check_nxdomain(subdomain):
    """Check if a subdomain resolves to NXDOMAIN."""
    try:
        dns.resolver.resolve(subdomain, 'A')
        return False  # The domain resolves correctly, not NXDOMAIN
    except dns.resolver.NXDOMAIN:
        return True  # NXDOMAIN response, potential for takeover
    except Exception as e:
        print(f"An error occurred while checking {subdomain}: {e}")
        return None  # In case of other DNS errors, decide how you want to handle these


#print("The result is: " + str(check_nxdomain('jeetcreates.com')))


# A list of patterns for known external services where assets can be claimed.
# You may need to update this list based on the services you're interested in.
known_external_services = [
    '*.s3.amazonaws.com',
    '*.blob.core.windows.net',
    '*.cloudapp.azure.com',
    '*.googleusercontent.com',
    '*.herokuapp.com',
    '*.web.app',
]

def check_cname_for_external_services(subdomain):
    """Check if the CNAME for a given subdomain points to an external service and checks the HTTP response for the fingerprint."""
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        print(f"CNAME records found for {subdomain}: {[str(rdata.target) for rdata in answers]}")
        for rdata in answers:
            print("PRINTING RDATA")
            print(rdata)
            print("RDATAPRINTEND")
            cname_target = str(rdata.target).lower()
            print(f"Checking {subdomain} alias {cname_target} against known services...")
            print("Alright jeet we begin debugging here")
            # Check if the CNAME points to any known external service
            for service in service_fingerprints:
                for pattern in service['cname']:
                    print("Currently checking pattern: "+ pattern)
                    regex_pattern = pattern.replace('.', r'\.').replace('*', r'.*')
                    if re.search(regex_pattern, cname_target):
                        print(f"Matching service found: {service['service']}")
                        fingerprint_match = check_for_fingerprint(subdomain, service['fingerprint'])
                        print(f"Fingerprint check for {subdomain} on {service['service']}: {fingerprint_match}")
                        if fingerprint_match:
                            print(f"Potential vulnerability found: {subdomain} points to {service['service']} with matching fingerprint.")
                            return True
                        else:
                            print(f"Fingerprint does not match for {service['service']}.")
    except dns.resolver.NoAnswer:
        print(f"No CNAME record found for {subdomain}.")
    except dns.resolver.NXDOMAIN:
        print(f"{subdomain} does not exist.")
    except Exception as e:
        print(f"An error occurred during CNAME resolution: {e}")
    return False

def check_for_fingerprint(subdomain, fingerprint):
    print("JEET U MADE IT")
    """Check the HTTP response of the subdomain for the given fingerprint."""
    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        print(f"HTTP Status for {subdomain}: {response.status_code}")
        content = response.text[:1000]  # Print the first 1000 characters of the response for debugging
        print(f"Snippet of webpage content for {subdomain}: {content}")
        
        # Simple string check (case-insensitive)
        if fingerprint.lower() in response.text.lower():
            print("Simple string match found.")
            return True
        
        # For more complex patterns, consider using regular expressions.
        # If you go this route, make sure your fingerprints in the JSON are valid regex patterns.
        # if re.search(fingerprint, response.text, re.IGNORECASE):
        #     print("Regex match found.")
        #     return True

    except requests.RequestException as e:
        print(f"Failed to fetch the webpage for {subdomain}: {e}")
    return False


def cname_check(cnames):
    vulnerable = []
    for cname in cnames:
        print(cname['name'])
        cname_target = check_cname(cname['name'])
        if cname_target:
            if check_http_response(cname['name']):
                vulnerable.append(cname['name'])
    return vulnerable

