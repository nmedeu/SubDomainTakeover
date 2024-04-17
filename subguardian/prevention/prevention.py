import logging
from txt_check import fetch_txt_records, check_for_vulnerabilities as check_txt_vulnerabilities
from mx_check import mx_check
from ns_check import ns_check
from cname_check import cname_check, check_cname_for_external_services
from aname_check import aname_check
import schedule
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def monitor_subdomains():
    subdomains = ['example1.yourdomain.com', 'example2.yourdomain.com']  # List of subdomains to monitor
    for subdomain in subdomains:
        # Check TXT records
        txt_vulnerabilities = check_txt_vulnerabilities(subdomain)
        if txt_vulnerabilities:
            for vulnerability in txt_vulnerabilities:
                logging.warning(f"TXT Alert: {vulnerability}")

        # Check CNAME records
        cname_vulnerabilities = cname_check(subdomain)
        if cname_vulnerabilities:
            for vulnerability in cname_vulnerabilities:
                logging.warning(f"CNAME Alert: {vulnerability}")

        # Check MX records
        mx_vulnerabilities = mx_check(subdomain)
        if mx_vulnerabilities:
            for vulnerability in mx_vulnerabilities:
                logging.warning(f"MX Alert: {vulnerability}")

        # Check NS records
        ns_vulnerabilities = ns_check(subdomain)
        if ns_vulnerabilities:
            for vulnerability in ns_vulnerabilities:
                logging.warning(f"NS Alert: {vulnerability}")

        # Check ANAME records
        aname_vulnerabilities = aname_check(subdomain)
        if aname_vulnerabilities:
            for vulnerability in aname_vulnerabilities:
                logging.warning(f"ANAME Alert: {vulnerability}")


        # Log if no vulnerabilities are found
        if not (txt_vulnerabilities or cname_vulnerabilities or mx_vulnerabilities or ns_vulnerabilities or aname_vulnerabilities):
            logging.info(f"No vulnerabilities found for {subdomain}")

def job():
    monitor_subdomains()

schedule.every().hour.do(job)

while True:
    schedule.run_pending()
    time.sleep(60)  # Sleep for a minute and then check if there's a job pending

