import dns.resolver
import re
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load vulnerability patterns for TXT records from a JSON file
try: 
    with open('txt_patterns.json', 'r') as f:
        txt_patterns = json.load(f)
        logging.info("TXT record vulnerability patterns loaded successfully.")
except FileNotFoundError as e:
    logging.error(f"TXT patterns file not found: {e}")
    txt_patterns = {}
except json.JSONDecodeError as e:
    logging.error(f"Error decoding TXT patterns JSON: {e}")
    txt_patterns = {}
except Exception as e:
    logging.error(f"Unexpected error loading TXT patterns: {e}")
    txt_patterns = {}

def fetch_txt_records(subdomain):
    """Fetch TXT records for a given subdomain."""
    records = {}
    try:
        answers = dns.resolver.resolve(subdomain, 'TXT')
        records[subdomain] = [rdata.to_text().strip('"') for rdata in answers.rrset]
    except dns.resolver.NoAnswer:
        logging.info(f"No TXT record found for {subdomain}.")
        records[subdomain] = []
    except Exception as e:
        logging.error(f"Error fetching TXT records for {subdomain}: {e}")
        records[subdomain] = []
    return records

def check_for_vulnerabilities(subdomain):
    """Check TXT records of a subdomain for potential takeover vulnerabilities."""
    txt_records = fetch_txt_records(subdomain)
    vulnerabilities = {}

    for record in txt_records[subdomain]:
        for service, patterns in txt_patterns.items():
            for pattern in patterns:
                if re.search(pattern, record):
                    reason = f"Matched {service} pattern '{pattern}' indicating possible vulnerability."
                    if subdomain in vulnerabilities:
                        vulnerabilities[subdomain].append(reason)
                    else:
                        vulnerabilities[subdomain] = [reason]
                    logging.warning(f"[VULNERABLE] {subdomain} might be vulnerable due to TXT record: {record}")
    if not vulnerabilities.get(subdomain):
        logging.info(f"No vulnerabilities found in TXT records for {subdomain}.")
        return {subdomain: ["No vulnerabilities detected."]}
    else:
        return vulnerabilities

def fetch_dns_records(subdomain, record_type):
    """Fetch other DNS records based on type."""
    records = {}
    try:
        answers = dns.resolver.resolve(subdomain, record_type)
        records[subdomain] = [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        logging.info(f"No {record_type} record found for {subdomain}.")
        records[subdomain] = []
    except Exception as e:
        logging.error(f"Error fetching {record_type} records for {subdomain}: {e}")
        records[subdomain] = []
    return records

def display_vulnerabilities(subdomains):
    """Display vulnerabilities for a list of subdomains."""
    for subdomain in subdomains:
        vulnerabilities = check_for_vulnerabilities(subdomain)
        if vulnerabilities:
            print(f"Vulnerabilities for {subdomain}:")
            for v in vulnerabilities[subdomain]:
                print(f" - {v}")
        else:
            print(f"No vulnerabilities found for {subdomain}.")

test_subdomains = ['www.bucrib.com', 'blog.bucrib.com', 'forms.bucrib.com']
display_vulnerabilities(test_subdomains)
