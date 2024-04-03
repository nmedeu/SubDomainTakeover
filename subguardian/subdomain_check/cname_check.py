import dns.resolver
import requests

def check_cname(subdomain):
    """Resolve the CNAME for a given subdomain."""
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            print(f"{subdomain} is an alias for {rdata.target}.")
            return str(rdata.target)
    except dns.resolver.NoAnswer:
        print(f"No CNAME record found for {subdomain}.")
        return None
    except Exception as e:
        print('lol')
        print(f"An error occurred: {e}")
        return None

def check_http_response(subdomain):
    """Check the HTTP response of the subdomain."""

    vulnerable = []

    try:
        response = requests.get(f"http://{subdomain}", timeout=5)
        print(f"HTTP Status Code for {subdomain}: {response.status_code}")
        if response.status_code == 404 or response.status_code == 410:
            vulnerable.append(subdomain)
            print("Possible takeover opportunity detected (HTTP 404/410)!")
        elif response.status_code == 200:
            print("Resource active (HTTP 200).")
        elif response.status_code == 403:
            vulnerable.append(subdomain)
            print("Possible misconfiguration detected (HTTP 403).")
    except requests.ConnectionError:
        print(f"Failed to establish a connection to {subdomain}.")
    except requests.Timeout:
        print(f"Request to {subdomain} timed out.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return vulnerable


def cname_check(cnames):

    vulnerable = []
    for cname in cnames:
        print(cname['name'])
        cname_target = check_cname(cname['name'])
        if cname_target:
            vulnerable.extend(check_http_response(cname['name']))
    
    return vulnerable

