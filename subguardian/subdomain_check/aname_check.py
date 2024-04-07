import socket
from urllib.parse import urlparse

def reverse_dns_lookup(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        return None

def extract_domain(url):
    parsed_uri = urlparse(url)
    # Extracts netloc (network location) and removes any www prefix
    domain = parsed_uri.netloc if parsed_uri.netloc else parsed_uri.path
    domain = domain.replace("www.", "")
    return domain

def check_domain_relation(queried_domain, expected_domain):
    # Simplified check: See if the expected domain is part of the queried domain
    return expected_domain in queried_domain

# Example usage
ip_address = '191.101.104.198'  # Example IP
expected_domain = 'jeetcreates.com'
resolved_domain = reverse_dns_lookup(ip_address)

print(resolved_domain)
# if resolved_domain:
#     queried_domain = extract_domain(f"http://{resolved_domain}")
#     if check_domain_relation(queried_domain, expected_domain):
#         print(f"The domain {resolved_domain} is related to {expected_domain}.")
#     else:
#         print(f"The domain {resolved_domain} is NOT related to {expected_domain}.")
# else:
#     print("Reverse DNS lookup failed.")


