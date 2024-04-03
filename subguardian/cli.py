# Standard Lib Modules
import socket
import sys
import argparse
import re
import os
import datetime

from netaddr import IPNetwork, IPRange
import netaddr

# External Modules
from .subdomain_enum.sublist3r import sublist3r
from .dnsrecon.dnsrecon import check_nxdomain_hijack, dnsrecon, socket_resolv
from .dnsrecon.lib.dnshelper import DnsHelper
from .lib.helper import *
from .subdomain_check.cname_check import cname_check


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
 \___ \| | | | '_ \| | |_ | | | |/ _` | '__/ _` | |/ _` | '_ \ 
 ____) | |_| | |_) | |__| | |_| | (_| | | | (_| | | (_| | | | |
|_____/ \__,_|_.__/ \_____|\__,_|\__,_|_|  \__,_|_|\__,_|_| |_|%s%s

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
    parser.error = parser_error
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


    # # Sublist3r

    # print(B + "Running Sublist3r ")
    # subdomains = sublist3r(domain, threads, savefile, silent=False, verbose=verbose, enable_bruteforce=enable_bruteforce)
    
    # #print(subdomains) # list of subdomains

    

    # # dnsrecon

    # print(B + "Running dnsrecon ")
    # records = dnsrecon(domain, types, type_map, res, request_timeout, do_output, xfr, yandex, do_crt, zonewalk, threads)
    # records = sort_records(records)


    # # add sublist3r subdomains into reords

    # records = unique_records(records)
    # records = add_sublist3r_if_cname_absent(records, subdomains)

    # print(records)


    # bucrib.com
    #records = {'A': [{'address': '185.199.108.153', 'name': 'subdomaintakeover1.github.io', 'type': 'A'}, {'address': '154.41.250.134', 'name': 'bucrib.com', 'type': 'A'}, {'address': '185.199.109.153', 'name': 'subdomaintakeover1.github.io', 'type': 'A'}, {'address': '185.199.108.153', 'name': 'nmedeu.github.io', 'type': 'A'}, {'address': '185.199.109.153', 'name': 'nmedeu.github.io', 'type': 'A'}, {'address': '185.199.110.153', 'name': 'nmedeu.github.io', 'type': 'A'}, {'address': '185.199.111.153', 'name': 'nmedeu.github.io', 'type': 'A'}, {'address': '185.199.111.153', 'name': 'subdomaintakeover1.github.io', 'type': 'A'}, {'address': '191.101.104.5', 'domain': 'bucrib.com', 'name': 'bucrib.com', 'type': 'A'}, {'address': '185.199.110.153', 'name': 'subdomaintakeover1.github.io', 'type': 'A'}], 'AAAA': [{'address': '2a02:4780:1e:4d74:359f:132b:e1f3:ebf3', 'domain': 'bucrib.com', 'name': 'bucrib.com', 'type': 'AAAA'}, {'address': '2a02:4780:1d:30ed:ee97:7895:49c9:e729', 'name': 'bucrib.com', 'type': 'AAAA'}], 'CNAME': [{'name': 'forms.bucrib.com', 'target': 'nmedeu.github.io', 'type': 'CNAME'}, {'name': 'blog.bucrib.com', 'target': 'subdomaintakeover1.github.io', 'type': 'CNAME'}], 'MX': [{'address': '172.65.182.103', 'domain': 'bucrib.com', 'exchange': 'mx1.hostinger.com', 'type': 'MX'}, {'address': '2606:4700:90:0:c1f8:f874:2386:b61f', 'domain': 'bucrib.com', 'exchange': 'mx2.hostinger.com', 'type': 'MX'}, {'address': '2606:4700:90:0:c1f8:f874:2386:b61f', 'domain': 'bucrib.com', 'exchange': 'mx1.hostinger.com', 'type': 'MX'}, {'address': '172.65.182.103', 'domain': 'bucrib.com', 'exchange': 'mx2.hostinger.com', 'type': 'MX'}], 'NS': [{'Version': '"2024.3.1"', 'address': '162.159.25.42', 'domain': 'bucrib.com', 'recursive': 'True', 'target': 'ns2.dns-parking.com', 'type': 'NS'}, {'Version': '', 'address': '2400:cb00:2049:1::a29f:192a', 'domain': 'bucrib.com', 'recursive': 'False', 'target': 'ns2.dns-parking.com', 'type': 'NS'}, {'Version': '', 'address': '2400:cb00:2049:1::a29f:18c9', 'domain': 'bucrib.com', 'recursive': 'False', 'target': 'ns1.dns-parking.com', 'type': 'NS'}, {'Version': '"2024.3.1"', 'address': '162.159.24.201', 'domain': 'bucrib.com', 'recursive': 'True', 'target': 'ns1.dns-parking.com', 'type': 'NS'}], 'SOA': [{'address': '2400:cb00:2049:1::a29f:18c9', 'domain': 'bucrib.com', 'mname': 'ns1.dns-parking.com', 'type': 'SOA'}, {'address': '162.159.24.201', 'domain': 'bucrib.com', 'mname': 'ns1.dns-parking.com', 'type': 'SOA'}], 'TXT': [{'domain': 'bucrib.com', 'name': 'bucrib.com', 'strings': 'v=spf1 include:_spf.mail.hostinger.com ~all', 'type': 'TXT'}, {'domain': 'bucrib.com', 'name': '_dmarc.bucrib.com', 'strings': 'v=DMARC1; p=none', 'type': 'TXT'}], 'sublist3r': [{'name': 'www.bucrib.com', 'type': 'subdomain'}]}
    
    # Jeetcreates.com
    records = {'A': [{'address': '185.230.63.171', 'name': 'jeetcreates.com', 'type': 'A'}, {'address': '185.230.63.171', 'domain': 'jeetcreates.com', 'name': 'jeetcreates.com', 'type': 'A'}, {'address': '185.230.63.107', 'name': 'jeetcreates.com', 'type': 'A'}, {'address': '185.230.63.186', 'domain': 'jeetcreates.com', 'name': 'jeetcreates.com', 'type': 'A'}, {'address': '185.230.63.107', 'domain': 'jeetcreates.com', 'name': 'jeetcreates.com', 'type': 'A'}, {'address': '185.230.63.186', 'name': 'jeetcreates.com', 'type': 'A'}], 'NS': [{'Version': '', 'address': '216.239.38.100', 'domain': 'jeetcreates.com', 'recursive': 'True', 'target': 'ns3.wixdns.net', 'type': 'NS'}, {'Version': '', 'address': '216.239.36.100', 'domain': 'jeetcreates.com', 'recursive': 'True', 'target': 'ns2.wixdns.net', 'type': 'NS'}], 'SOA': [{'address': '216.239.36.100', 'domain': 'jeetcreates.com', 'mname': 'ns2.wixdns.net', 'type': 'SOA'}], 'sublist3r': [{'name': 'www.jeetcreates.com', 'type': 'subdomain'}]}


    print(records['CNAME'])
    # Check CNAME vulnearbilities


    # print(type(records['sublist3r']))

    # print(cname_check(records['sublist3r']))


