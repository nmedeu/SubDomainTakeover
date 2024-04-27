import requests
import logging
import dns.resolver

# Cloudflare API credentials and configurations
CLOUDFLARE_EMAIL = 'centraldeveloper13@gmail.com'
CLOUDFLARE_API_KEY = '4761d16c2fd5d394c6089414b6509e3e7a5e2'
CLOUDFLARE_ZONE_ID = '619807a78c04c7e36945a10b65d28d76'


headers = {
    "X-Auth-Email": CLOUDFLARE_EMAIL,
    "X-Auth-Key": CLOUDFLARE_API_KEY,
    "Content-Type": "application/json"
}


def list_whatever():
    url = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/dns_records"
    response = requests.get(url, headers=headers)
    return response.text


# subdomain = 'forms.bucrib.com'

# results = list_whatever()

# print(type(results))


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


print(find_id('blog.bucrib.com'))








