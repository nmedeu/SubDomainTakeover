import dns.resolver
import dns.query
import dns.zone
import whois
import datetime
import ipaddress

# Helper function, check whether its a IPv4 or IPv6 address
def check_ip_version(ip_address):
    try:
        return "IPv4" if type(ipaddress.ip_address(ip_address)) is ipaddress.IPv4Address else "IPv6"
    except ValueError:
        return "Invalid IP address"

def check_if_orphaned(ns_record):
    ip = ns_record['address']
    address_type = check_ip_version(ip)
    ns_domain = ns_record['target']

    if (address_type == 'IPv4'):
        try:
            # Check for A record (IPv4)
            dns.resolver.resolve(ns_domain, 'A')
            print(f"IPv4 address found for Name Server {ns_domain}")
            return False, address_type
        except dns.resolver.NoAnswer:
            print(f"No IPv4 address found for Name Server {ns_domain}")
            return True, address_type
    elif (address_type == 'IPv6'):
        try:
            # Check for AAAA record (IPv6)
            dns.resolver.resolve(ns_domain, 'AAAA')
            print(f"IPv6 address found for Name Server {ns_domain}")
            return False, address_type
        except dns.resolver.NoAnswer:
            print(f"No IPv6 address found for Name Server {ns_domain}")
            return True, address_type
    else:
        print(address_type)
        return False, address_type


def check_if_expired(ns_record):
    ns_domain = str(ns_record['target'])
    ns_domain = ns_domain.split('.')[-2] + '.' + ns_domain.split('.')[-1]

    try:
        ns_whois = whois.whois(ns_domain)
        if isinstance(ns_whois.expiration_date, list):
            expiration_date = ns_whois.expiration_date[0]
        else:
            expiration_date = ns_whois.expiration_date

        if expiration_date and expiration_date < datetime.datetime.now():
            print(f"NS domain {ns_domain} is expired")
            return True
        else:
            print(f"NS domain {ns_domain} has not expired")
            return False
    except whois.parser.PywhoisError:
        print(f"WHOIS data not found for NS domain {ns_domain}")
        return False


def check_ns_status(ns_record):
    ns_target = str(ns_record['target'])
    domain = str(ns_record['domain'])
    ip = str(ns_record['address'])
    address_type = check_ip_version(ip)
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ip]

    try:
        response = resolver.resolve(domain)
        if response:
            print(f"NS domain {ns_target} is up and responding.")
            return False, ip, address_type
    except Exception as e:
        print(f"NS domain {ns_target} is not responding or may be down.")
        return True, ip, address_type


def ns_check(ns_records):
    vulnerability = {}
    
    for ns_record in ns_records:
        print("ns_record now checking is: ", ns_record)

        # Check for orphaned DNS records
        orphaned, ip_type = check_if_orphaned(ns_record)
        if orphaned:
            vulnerability[ns_record['target']] = f'{ip_type} orphaned'

        # Check for expired domain for current NS record
        expired = check_if_expired(ns_record)
        if expired:
            vulnerability[ns_record['target']] = 'expired'

        # Check whether the current ns is down
        down, ip, ip_type_s = check_ns_status(ns_record)
        if down and ip_type_s == 'IPv6':
            vulnerability[ns_record['target']] = f'{ip} might be down or IPv6 is not supported by the server'
        elif down and ip_type_s == 'IPv4':
            vulnerability[ns_record['target']] = f'{ip} might be down'

    
    return vulnerability