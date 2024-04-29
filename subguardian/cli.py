# Standard Lib Modules
import socket
import sys
import argparse
import re
import os
import datetime

from dotenv import load_dotenv
from netaddr import IPNetwork, IPRange
import netaddr

# External Modules
from .subdomain_enum.sublist3r import sublist3r
from .dnsrecon.dnsrecon import check_nxdomain_hijack, dnsrecon, socket_resolv
from .dnsrecon.lib.dnshelper import DnsHelper
from .lib.helper import *
from .subdomain_check.cname_check import cname_check
from .subdomain_check.a_check import a_check
from .subdomain_check.mx_check import mx_check
from .subdomain_check.ns_check import ns_check
from .subdomain_check.txt_check import txt_check
from .prevention.cloudfare import *



CONFIG = {'disable_check_recursion': False, 'disable_check_bindversion': False}

# Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')

# Console Colors
if is_windows:
    # No colors for windows >:3
    print("[!] Error: Coloring libraries not installed, no coloring will be used [Check the readme]")
    G = Y = B = R = W = G = Y = B = R = W = ''
else:
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white

def no_color():
    global G, Y, B, R, W
    G = Y = B = R = W = ''


def banner():
    print("""%s
  _____       _      _____                     _ _             
 / ____|     | |    / ____|                   | (_)            
| (___  _   _| |__ | |  __ _   _  __ _ _ __ __| |_  __ _ _ __  
 \\___ \\| | | | '_ \\| | |_ | | | |/ _` | '__/ _` | |/ _` | '_ \\ 
 ____) | |_| | |_) | |__| | |_| | (_| | | | (_| | | (_| | | | |
|_____/ \\__,_|_.__/ \\_____|\\__,_|\\__,_|_|  \\__,_|_|\\__,_|_| |_|%s%s

                # Team 1 | EC521
    """ % (R, W, Y))


def process_range(arg):
    """
    This function will take a string representation of a range for IPv4 or IPv6 in
    CIDR or Range format and return a list of IPs.
    """
    ip_list = []

    ranges_raw_list = list(set(arg.strip().split(',')))
    for entry in ranges_raw_list:
        try:
            range_vals = []
            if re.match(r'\S*/\S*', entry):
                ip_list.append(IPNetwork(entry))

            elif re.match(r'\S*-\S*', entry):
                range_vals.extend(entry.split('-'))
                if len(range_vals) == 2:
                    ip_list.append(IPRange(range_vals[0], range_vals[1]))
            else:
                parser_error(f'Range: {entry} provided is not valid')
        except Exception:
            print(Exception)
            parser_error(f'Range: {entry} provided is not valid')

    return ip_list


# Define Args
def parse_args():
    # parse the args
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser.error = parser_error # type: ignore
    parser._optionals.title = "OPTIONS"

    # sublist3r args
    parser.add_argument(
            '-d', '--domain', 
            help="Target Domain", 
            required=True)
    parser.add_argument(
            '-b', '--bruteforce', 
            help='Enable the subbrute bruteforce module', 
            default=False)
    parser.add_argument(
            '-v', '--verbose', 
            help='Enable Verbosity and display results in realtime', 
            nargs='?', 
            default=False)
    parser.add_argument(
            '-t', '--threads', 
            help='Number of threads to use for subbrute bruteforce', 
            type=int, 
            default=30)
    parser.add_argument(
            '-o', '--output', 
            help='Save the results to text file')

    # dnsrecon args
    parser.add_argument(
            '-n', '--name_server',
            type=str,
            dest='ns_server',
            help='Domain server to use. If none is given, the SOA of the target will be used. Multiple servers can be specified using a comma separated list.',
        )
    parser.add_argument(
            '-a', 
            help='If enabled, do not perform AXFR with standard enumeration.', 
            action='store_true', 
            default=False)
    parser.add_argument(
            '-y',
            help='If enabled, do not perform Yandex enumeration with standard enumeration.',
            action='store_true',
            default=False
        )
    parser.add_argument(
            '-k',
            help='If enabled, do not perform crt.sh enumeration with standard enumeration.',
            action='store_true',
        )
    parser.add_argument(
            '-z',
            help='If enabled, does not perform a DNSSEC zone walk with standard enumeration.',
            action='store_true',
        )
    parser.add_argument(
            '--lifetime',
            type=float,
            dest='lifetime',
            default=3.0,
            help='Time to wait for a server to respond to a query. default is 3.0',
        )
    parser.add_argument(
            '--tcp',
            dest='tcp',
            help='Use TCP protocol to make queries.',
            action='store_true',
        )
    parser.add_argument(
            '--disable_check_recursion',
            help='Disables check for recursion on name servers',
            action='store_true',
        )
    parser.add_argument(
            '--disable_check_bindversion',
            help='Disables check for BIND version on name servers',
            action='store_true',
        )
    
    # Prevention args
    parser.add_argument(
            '-p', '--prevent',
            type=str,
            dest='prevent_hosts',
            help="""Choose DNS hosts you use to prevent subdomain takeover, and it will delete all the vulnearble DNS records.
Possible types:
    cloudfare:       prevents cloudfare misconfigurations,

    Rest coming soon. 
    """,
    )

    return parser.parse_args()

def parser_error(errmsg):
    banner()
    print("Usage: python " + sys.argv[0] + " [Options] use -h for help")
    print(R + "Error: " + errmsg + W)
    sys.exit()


def main():
    args = parse_args()
    domain = args.domain
    threads = args.threads
    enable_bruteforce = args.bruteforce
    verbose = args.verbose
    savefile = args.output

    # Check if prevent is enabled, if so check for input
    valid_types = ['cloudfare'] # append more types as we update the tool


    prevent_hosts = args.prevent_hosts
    host_types = []
    if prevent_hosts:
        if prevent_hosts:
            prevent_hosts = prevent_hosts.lower().strip()

            # we create a dynamic regex specifying min and max type length
            # and max number of possible scan types
            min_type_len = len(min(valid_types, key=len))
            max_type_len = len(max(valid_types, key=len))
            type_len = len(valid_types)
            dynamic_regex = f'^([a-z]{{{min_type_len},{max_type_len}}},?){{,{type_len}}}$'

            type_match = re.match(dynamic_regex, prevent_hosts)
            if not type_match:
                parser_error('This type of scan is not valid')
                sys.exit(1)

            incorrect_types = [t for t in prevent_hosts.split(',') if t not in valid_types]
            if incorrect_types:
                incorrect_types_str = ','.join(incorrect_types)
                parser_error(f'This type of scan is not in the list: {incorrect_types_str}')
                sys.exit(1)

            host_types = list(set(prevent_hosts.split(',')))

    load_dotenv()
    for host in host_types:
        if host == "cloudfare":
            required_vars = ["CLOUDFLARE_EMAIL", "CLOUDFLARE_API_KEY", "CLOUDFLARE_ZONE_ID"]
            # Check each variable
            for var in required_vars:
                value = os.getenv(var)
                if value == '':
                    parser_error(f"{var} should not be empty")



    # a "map" that specifies if a type of scan needs
    # the domain and the dictionary
    type_map = {
        'std': {'domain': True, 'dictionary': False},
        'brt': {'domain': True, 'dictionary': False},
    }

    # here domain can be assigned. If it is not required
    # domain will be None
    domain = args.domain

    types = ['std']

    # validate user provided name server(s)
    ns_server = []
    if args.ns_server:
        ns_raw_list = list(set(args.ns_server.strip().split(',')))
        for entry in ns_raw_list:
            # Resolve in the case if FQDN
            answer = socket_resolv(entry)
            # Check we actually got a list
            if len(answer) > 0:
                # We will use the first IP found as the NS
                ns_server.append(answer[0][2])
            else:
                # Exit if we cannot resolve it
                parser_error(f"Could not resolve NS server provided and server doesn't appear to be an IP: {entry}")

            if check_nxdomain_hijack(socket.gethostbyname(entry)):
                continue

            if netaddr.valid_glob(entry):
                ns_server.append(entry)
                continue

        # User specified name servers but none of them validated
        if not ns_server:
            parser_error('Please specify valid name servers.')
             

        # remove duplicated
        ns_server = list(set(ns_server))

    request_timeout = float(args.lifetime)


    # this flag summarizes if the program has to output
    # do_output = bool(output_file or results_db or csv_file or json_file)
    do_output = True

    verbose = args.verbose
    CONFIG['disable_check_recursion'] = args.disable_check_recursion
    CONFIG['disable_check_bindversion'] = args.disable_check_bindversion

    xfr = True
    yandex = True
    do_crt = True   
    zonewalk = True

    if args.a:
        xfr = False
    if args.y:
        yandex = False
    if args.k:
        do_crt = False
    if args.z:
        zonewalk = False

    proto = 'tcp' if args.tcp else 'udp'

    # Set the resolver
    res = DnsHelper(domain, ns_server, request_timeout, proto)


    banner()


    # Sublist3r
    print(B + "Running Sublist3r ")
    subdomains = sublist3r(domain, threads, savefile, silent=False, verbose=verbose, enable_bruteforce=enable_bruteforce)
    

    # dnsrecon
    print(B + "Running dnsrecon ")
    records = dnsrecon(domain, types, type_map, res, request_timeout, do_output, xfr, yandex, do_crt, zonewalk, threads)
    records = sort_records(records)


    # add sublist3r subdomains into reords
    records = unique_records(records)
    records = add_sublist3r_if_cname_absent(records, subdomains)



    cnames = []
    # # If user provided API keys for their DNS, then also use that information
    # if host_types:
    #     for host in host_types:
    #         if host == 'cloudfare':
    #             cloudfare_records = fetch_all_dns_records()
    #             for record in cloudfare_records:
    #                 if record['type'] in records:
    #                     print()
    #                     records[record['type']].append(record)
    #                 else:
    #                     records[record['type']] = record


    # Check for vulnerable CNAME records
    if 'cname' in records:
        cnames.extend(records['cname'])
    if 'sublist3r' in records:
        cnames.extend(records['sublist3r'])

    cname_vulnerabilities = cname_check(cnames)
    
    # Check for vulnerable A records
    a_vulnerabilities = {}
    if 'A' in records:
        a_vulnerabilities = a_check(records['A'])

    # Check for vulnerable NS records
    ns_vulnerabilities = {}
    if 'NS' in records:
        ns_vulnerabilities = ns_check(records['NS'])

    # Check for vulnerable MX records
    mx_vulnerabilities = {}
    if 'MX' in records:
        mx_vulnerabilities = mx_check(records['MX'])

    # Check for vulnerable TXT records
    txt_vulnerabilities = {}
    if 'TXT' in records:
        txt_vulnerabilities = txt_check(records['TXT'])


    
    print()
    print("CNAMES", cname_vulnerabilities)
    print()
    print("A RECORDS", a_vulnerabilities)
    print()
    print("NS RECORDS", ns_vulnerabilities)
    print()
    print("MX RECORDS", mx_vulnerabilities)
    print()
    print("TXT RECRODS", txt_vulnerabilities)
    print()
    print()

    # print(records)
    # print()
    # print(subdomains)

    # Save the vulnerabilities in a text file
    current_directory = os.getcwd()
    output_directory = os.path.join(current_directory, 'output')

    # Check if the 'output' directory exists, if not, create it
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
    vulnerability_report_log = f'{output_directory}/vulnerability_report.txt'

    # Function to format the dictionary into a string
    def format_dict_to_string(title, dictionary):
        result = f"{title}:\n"
        for key, values in dictionary.items():
            result += f"{key}:\n"
            for value in values:
                result += f"  - {value}\n"
        result += "\n"
        return result

    # Open the file and write the formatted string to it
    with open(vulnerability_report_log, 'w') as file:
        if (cname_vulnerabilities == {}):
            file.write("CNAME Vulnerabilities: N/A\n")
            file.write("\n")
        else:
            file.write(format_dict_to_string('CNAME Vulnerabilities', cname_vulnerabilities))
        if (a_vulnerabilities == {}):
            file.write("A Records Vulnerabilities: N/A\n")
            file.write("\n")
        else:
            file.write(format_dict_to_string('A Records Vulnerabilities', a_vulnerabilities))
        if (ns_vulnerabilities == {}):
            file.write("NS Records Vulnerabilities: N/A\n")
            file.write("\n")
        else:
            file.write(format_dict_to_string('NS Records Vulnerabilities', ns_vulnerabilities))
        if (mx_vulnerabilities == {}):
            file.write("MX Records Vulnerabilities: N/A\n")
            file.write("\n")
        else:
            file.write(format_dict_to_string('MX Records Vulnerabilities', mx_vulnerabilities))
        if (txt_vulnerabilities == {}):
            file.write("TXT Records Vulnerabilities: N/A\n")
            file.write("\n")
        else:
            file.write(format_dict_to_string('TXT Records Vulnerabilities', txt_vulnerabilities))


    # Initialize an empty set to hold unique keys
    vulnerable_subdomains_set = set()

    # Combine all dictionaries' keys into the set
    vulnerable_subdomains_set.update(cname_vulnerabilities.keys())
    vulnerable_subdomains_set.update(a_vulnerabilities.keys())
    # vulnerable_subdomains_set.update(ns_vulnerabilities.keys())
    # vulnerable_subdomains_set.update(mx_vulnerabilities.keys())
    vulnerable_subdomains_set.update(txt_vulnerabilities.keys())

    # Convert the set to a list
    vulnerable_subdomains = list(vulnerable_subdomains_set)
    print("vulnerable_subdomains: ", vulnerable_subdomains)

    # Delete vulnerable records if possible
    deleted_subdomain = {}
    failed_subdomain = {}
    if host_types:
        for host in host_types:
            if host == 'cloudfare':
                deleted_subdomain, failed_subdomain = cloudfare_prevention(vulnerable_subdomains)

    # Save the deleted DNS records in a text file
    deletion_report_log = f'{output_directory}/deletion_report.txt'

    # Open the file and write the formatted string to it
    with open(deletion_report_log, 'w') as file:
        if (deleted_subdomain == {}):
            file.write('Successfully deleted DNS records: N/A\n')
            file.write("\n")
        else:
            file.write(format_dict_to_string('Successfully deleted DNS records', deleted_subdomain))
        if (failed_subdomain == {}):
            file.write("Unsuccessfully deleted DNS records: N/A\n")
            file.write("\n")
        else:
            file.write(format_dict_to_string('Unsuccessfully deleted DNS records', failed_subdomain))

    print("Done.")


