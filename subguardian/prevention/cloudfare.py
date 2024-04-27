import requests
import logging
import dns.resolver

# Initialize the logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Cloudflare API credentials and configurations
CLOUDFLARE_EMAIL = 'centraldeveloper13@gmail.com'
CLOUDFLARE_API_KEY = '4761d16c2fd5d394c6089414b6509e3e7a5e2'
CLOUDFLARE_ZONE_ID = '619807a78c04c7e36945a10b65d28d76'

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


def delete_dns_records(subdomains):
    """
    Delete DNS record for the subdomain using Cloudflare API.
    """
    for subdomain in subdomains:
        record_id = find_id(subdomain)
        # Delete the DNS recrod
        delete_url = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/dns_records/{record_id}"
        delete_response = requests.delete(delete_url, headers=headers)
        if delete_response.status_code == 200:
            logging.info(f"Successfully deleted DNS record for {subdomain}.")
        else:
            logging.error(f"Failed to delete DNS record for {subdomain}: {delete_response.text}")

