import dns.resolver
import requests


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
        print('lol')
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

    return 


def cname_check(cnames):
    vulnerable = []
    for cname in cnames:
        print(cname['name'])
        cname_target = check_cname(cname['name'])
        if cname_target:
            if check_http_response(cname['name']):
                vulnerable.append(cname['name'])
    return vulnerable

