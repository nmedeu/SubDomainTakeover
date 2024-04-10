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

def fetch_txt_records(subdomain):
    """Fetch TXT records for a given subdomain."""
    try:
        answers = dns.resolver.resolve(subdomain, 'TXT')
        return [str(rdata.strings[0], 'utf-8') for rdata in answers]
    except dns.resolver.NoAnswer:
        logging.warning(f"No TXT record found for {subdomain}.")
        return []
    except Exception as e:
        logging.error(f"An error occurred while fetching TXT records for {subdomain}: {e}")
        return []

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