import requests
import logging
# import dns.resolver
import os
from dotenv import load_dotenv

load_dotenv()

# Cloudflare API credentials and configurations

CLOUDFLARE_EMAIL = os.getenv('CLOUDFLARE_EMAIL')
CLOUDFLARE_API_KEY = os.getenv('CLOUDFLARE_API_KEY')
CLOUDFLARE_ZONE_ID = os.getenv('CLOUDFLARE_ZONE_ID')
    

headers = {
    "X-Auth-Email": CLOUDFLARE_EMAIL,
    "X-Auth-Key": CLOUDFLARE_API_KEY,
    "Content-Type": "application/json"
}


def fetch_all_dns_records():
    """
    Fetch all DNS records from a Cloudflare zone handling pagination.
    """
    all_records = []

    url = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/dns_records"
    response = requests.get(url, headers=headers)
    data = response.json()

    if response.status_code == 200 and data['success']:
        all_records.extend(data['result'])
    else:
        logging.error("Failed to fetch DNS records: " + response.text)

    return all_records


def find_id(subdomain):
    """
    List and print all DNS records.
    """
    records = fetch_all_dns_records()
    for record in records:
        if record['name'] == subdomain:
            return record['id']
    return None


def cloudfare_prevention(subdomains):
    """
    Delete DNS record for the subdomain using Cloudflare API.
    """
    deleted_subdomain = {}
    failed_subdomain = {}
    for subdomain in subdomains:
        record_id = find_id(subdomain)
        # Delete the DNS recrod
        delete_url = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/dns_records/{record_id}"
        delete_response = requests.delete(delete_url, headers=headers)
        if delete_response.status_code == 200:
            logging.info(f"Successfully deleted DNS record for {subdomain}.")
            deleted_subdomain.append(subdomain)
        else:
            logging.error(f"Failed to delete DNS record for {subdomain}: {delete_response.text}")
            failed_subdomain.append(subdomain)
    
    return deleted_subdomain, failed_subdomain

# records = fetch_all_dns_records()

# for record in records:

#     print(record)