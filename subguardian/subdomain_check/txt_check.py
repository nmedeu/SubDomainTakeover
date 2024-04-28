import dns.resolver
import re
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def load_txt_patterns():
    # Load vulnerability patterns for TXT records from a JSON file
    try: 
        with open('subguardian/subdomain_check/txt_patterns.json', 'r') as f:
            txt_patterns = json.load(f)
            #logging.info("TXT record vulnerability patterns loaded successfully.")
    except FileNotFoundError as e:
        #logging.error(f"TXT patterns file not found: {e}")
        txt_patterns = {}
    except json.JSONDecodeError as e:
        #logging.error(f"Error decoding TXT patterns JSON: {e}")
        txt_patterns = {}
    except Exception as e:
        #logging.error(f"Unexpected error loading TXT patterns: {e}")
        txt_patterns = {}
    return txt_patterns

def txt_check(txt_records):
    """Check TXT records of a subdomain for potential takeover vulnerabilities."""
    txt_patterns = load_txt_patterns()
    vulnerabilities = {}

    for record in txt_records:
        for service, patterns in txt_patterns.items():
            for pattern in patterns:
                if re.search(pattern, record['strings']):
                    reason = f"Matched {service} pattern '{pattern}' indicating possible vulnerability."
                    if record['name'] in vulnerabilities:
                        vulnerabilities[record['name']].append(reason)
                    else:
                        vulnerabilities[record['name']] = [reason]
                    logging.warning(f"[VULNERABLE] {record['name']} might be vulnerable due to TXT record: {record}")
    return vulnerabilities
