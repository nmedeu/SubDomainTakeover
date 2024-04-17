import dns.resolver
import re
import json
import logging

# logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load vulnerability patterns for TXT records from a JSON file
try: 
    with open('txt_patterns.json', 'r') as f:
        txt_patterns = json.load(f)
        logging.info("TXT record vulnerability patterns loaded successfully.")
except Exception as e:
    logging.error(f"Failed to load TXT vulnerability patterns: {e}")
    txt_patterns = {}

import dns.resolver

def fetch_txt_records(subdomain):
    """Fetch TXT records for a given subdomain."""
    records = {}
    try:
        answers = dns.resolver.resolve(subdomain, 'TXT')
        if answers.rrset is not None:
            records[subdomain] = [rdata.to_text() for rdata in answers.rrset]
        else:
            records[subdomain] = []
    except dns.resolver.NoAnswer:
        print(f"No TXT record found for {subdomain}.")
        records[subdomain] = []
    except Exception as e:
        print(f"An error occurred while fetching TXT records for {subdomain}: {e}")
        records[subdomain] = []
    return records


def check_for_vulnerabilities(subdomain):
    """Check TXT records of a subdomain for potential takeover vulnerabilities."""
    txt_records = fetch_txt_records(subdomain)
    vulnerable_records = []

    if not txt_records:
        logging.info(f"No TXT records to analyze for {subdomain}.")
        return vulnerable_records

    for record in txt_records:
        for service, patterns in txt_patterns.items():
            for pattern in patterns:
                if re.search(pattern, record):
                    vulnerable_records.append((subdomain, service, record))
                    logging.warning(f"[VULNERABLE] {subdomain} might be vulnerable due to TXT record ({service}): {record}")

    if not vulnerable_records:
        logging.info(f"No vulnerabilities found in TXT records for {subdomain}.")

    return vulnerable_records