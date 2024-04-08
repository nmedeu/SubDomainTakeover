import dns.resolver
import dns.query
import dns.zone
import whois
import datetime
import socket


def check_if_orphaned(ns_record):
    vulnerability = []
    try:
        # Check for A record (IPv4)
        dns.resolver.resolve(ns_record['target'], 'A')
        print(f"IPv4 address found for Name Server {ns_record['target']}")
    except dns.resolver.NoAnswer:
        print(f"No IPv4 address found for Name Server {ns_record['target']}")
        vulnerability.append(ns_record['domain'])

    try:
        # Check for AAAA record (IPv6)
        dns.resolver.resolve(ns_record['target'], 'AAAA')
        print(f"IPv6 address found for Name Server {ns_record['target']}")
    except dns.resolver.NoAnswer:
        print(f"No IPv6 address found for Name Server {ns_record['target']}")
        vulnerability.append(ns_record['domain'])

    return vulnerability


def check_if_expired(ns_record):
    vulnerability = []

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
            vulnerability.append(ns_domain)
        else:
            print(f"NS domain {ns_domain} has not expired")
    except whois.parser.PywhoisError:
        print(f"WHOIS data not found for NS domain {ns_domain}")
        vulnerability.append(ns_domain)
    
    return vulnerability


def ns_check(ns_records):
    vulnerability = []
    
    for ns_record in ns_records:
        print("ns_record now checking is: ", ns_record)

        # Check for orphaned DNS records
        vulnerability.extend(check_if_orphaned(ns_record))

        # Check for expired domain for current NS record
        vulnerability.extend(check_if_expired(ns_record))

    
    return vulnerability