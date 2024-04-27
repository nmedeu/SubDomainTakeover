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

def monitor_subdomains(cname_vulnerabilities, txt_vulnerabilities, mx_vulnerabilities, ns_vulnerabilities, aname_vulnerabilities):
        # Check TXT records
        if txt_vulnerabilities:
            for vulnerability in txt_vulnerabilities:
                logging.warning(f"TXT Alert: {vulnerability}")

        # Check CNAME records
        if cname_vulnerabilities:
            for vulnerability in cname_vulnerabilities:
                logging.warning(f"CNAME Alert: {vulnerability}")

        # Check MX records
        if mx_vulnerabilities:
            for vulnerability in mx_vulnerabilities:
                logging.warning(f"MX Alert: {vulnerability}")

        # Check NS records
        if ns_vulnerabilities:
            for vulnerability in ns_vulnerabilities:
                logging.warning(f"NS Alert: {vulnerability}")

        # Check ANAME records
        if aname_vulnerabilities:
            for vulnerability in aname_vulnerabilities:
                logging.warning(f"ANAME Alert: {vulnerability}")


        # Log if no vulnerabilities are found
        if not (txt_vulnerabilities or cname_vulnerabilities or mx_vulnerabilities or ns_vulnerabilities or aname_vulnerabilities):
            print(f"No vulnerabilities found for")

def job(cname_vulnerabilities, txt_vulnerabilities, mx_vulnerabilities, ns_vulnerabilities, aname_vulnerabilities):
    monitor_subdomains(cname_vulnerabilities, txt_vulnerabilities, mx_vulnerabilities, ns_vulnerabilities, aname_vulnerabilities)

schedule.every().hour.do(job)

while True:
    schedule.run_pending()
    time.sleep(60)  # Sleep for a minute and then check if there's a job pending

