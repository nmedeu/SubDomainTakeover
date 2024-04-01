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

    # sublist3r args
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Target Domain", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module', nargs='?', default=False)
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime', nargs='?', default=False)
    parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument('-o', '--output', help='Save the results to text file')

    # dnsrecon args
    parser.add_argument(
            '-n',
            '--name_server',
            type=str,
            dest='ns_server',
            help='Domain server to use. If none is given, the SOA of the target will be used. Multiple servers can be specified using a comma separated list.',
        )
    parser.add_argument(
            '-r',
            '--range',
            type=str,
            dest='range',
            help='IP range for reverse lookup brute force in formats   (first-last) or in (range/bitmask).',
        )
    parser.add_argument(
            '-D',
            '--dictionary',
            type=str,
            dest='dictionary',
            help='Dictionary file of subdomain and hostnames to use for brute force.',
        )
    parser.add_argument(
            '-f',
            help='Filter out of brute force domain lookup, records that resolve to the wildcard defined IP address when saving records.',
            action='store_true',
        )
    parser.add_argument('-a', help='Perform AXFR with standard enumeration.', action='store_true')
    parser.add_argument(
            '-s',
            help='Perform a reverse lookup of IPv4 ranges in the SPF record with standard enumeration.',
            action='store_true',
        )
    parser.add_argument(
            '-k',
            help='Perform crt.sh enumeration with standard enumeration.',
            action='store_true',
        )
    parser.add_argument(
            '-w',
            help='Perform deep whois record analysis and reverse lookup of IP ranges found through Whois when doing a standard enumeration.',
            action='store_true',
        )
    parser.add_argument(
            '-z',
            help='Performs a DNSSEC zone walk with standard enumeration.',
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
    parser.add_argument('--db', type=str, dest='db', help='SQLite 3 file to save found records.')
    parser.add_argument('-x', '--xml', type=str, dest='xml', help='XML file to save found records.')
    parser.add_argument(
            '-c',
            '--csv',
            type=str,
            dest='csv',
            help='Save output to a comma separated value file.',
        )
    parser.add_argument('-j', '--json', type=str, dest='json', help='save output to a JSON file.')
    parser.add_argument(
            '--iw',
            help='Continue brute forcing a domain even if a wildcard record is discovered.',
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
    parser.add_argument(
                '--type',
                type=str,
                dest='type',
                help="""Type of enumeration to perform.
    Possible types:
        std:      SOA, NS, A, AAAA, MX and SRV.
        rvl:      Reverse lookup of a given CIDR or IP range.
        brt:      Brute force domains and hosts using a given dictionary.
        srv:      SRV records.
        axfr:     Test all NS servers for a zone transfer.
        bing:     Perform Bing search for subdomains and hosts.
        yand:     Perform Yandex search for subdomains and hosts.
        crt:      Perform crt.sh search for subdomains and hosts.
        snoop:    Perform cache snooping against all NS servers for a given domain, testing
                all with file containing the domains, file given with -D option.

        tld:      Remove the TLD of given domain and test against all TLDs registered in IANA.
        zonewalk: Perform a DNSSEC zone walk using NSEC records.""",
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
        'axfr': {'domain': True, 'dictionary': False},
        'std': {'domain': True, 'dictionary': False},
        'srv': {'domain': True, 'dictionary': False},
        'tld': {'domain': True, 'dictionary': False},
        'bing': {'domain': True, 'dictionary': False},
        'yand': {'domain': True, 'dictionary': False},
        'crt': {'domain': True, 'dictionary': False},
        'rvl': {'domain': False, 'dictionary': False},
        'zonewalk': {'domain': True, 'dictionary': False},
        'brt': {'domain': True, 'dictionary': True},
        'snoop': {'domain': False, 'dictionary': True},
    }
    valid_types = type_map.keys()

    #
    # Parse options
    #


    # validating type param which is in the form: type1,type2,...,typeN
    # if the pattern is not correct or if there is an unknown type we exit
    type_arg = args.type
    types = []
    if type_arg:
        type_arg = type_arg.lower().strip()

        # we create a dynamic regex specifying min and max type length
        # and max number of possible scan types
        min_type_len = len(min(valid_types, key=len))
        max_type_len = len(max(valid_types, key=len))
        type_len = len(valid_types)
        dynamic_regex = f'^([a-z]{{{min_type_len},{max_type_len}}},?){{,{type_len}}}$'

        type_match = re.match(dynamic_regex, type_arg)
        if not type_match:
            parser_error('This type of scan is not valid')

        incorrect_types = [t for t in type_arg.split(',') if t not in valid_types]
        if incorrect_types:
            incorrect_types_str = ','.join(incorrect_types)
            parser_error(f'This type of scan is not in the list: {incorrect_types_str}')
             

        types = list(set(type_arg.split(',')))

    # validating range
    rvl_ip_list = []
    if args.range:
        rvl_ip_list = process_range(args.range)
        # if the provided range is not valid, we exit
        if not rvl_ip_list:
            parser_error('Invalid Address/CIDR or Address Range provided.')
             

        # otherwise, we update a type list
        if 'rvl' not in types:
            types.append('rvl')
         

    # here domain can be assigned. If it is not required
    # domain will be None
    domain = args.domain

    # if we don't have any types, but we have a domain
    # we will perform a general DNS enumeration (type: std),
    # so we add it to the types!
    if not types and domain:
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

    # validating dictionary parameter
    dictionary_required = []
    if types:
        # combining the types and the type_map, we obtain
        # dictionary_required, which is a list of bool
        # where True means that a dictionary file is required
        dictionary_required = [type_map[t]['dictionary'] for t in types]

    dictionary = ''
    if any(dictionary_required):
        # we generate a list of possible dictionary files
        script_dir = os.path.dirname(os.path.realpath(__file__)) + os.sep
        dictionaries = ['/etc/dnsrecon/namelist.txt', script_dir + 'namelist.txt']

        # if the user has provided a custom dictionary file,
        # we insert it as the first entry of the list
        if args.dictionary:
            args.dictionary = args.dictionary.strip()
            dictionaries.insert(0, args.dictionary)
        else:
            print('No dictionary file has been specified.')

        # we individuate the first valid dictionary file,
        # among those in the list
        for dict_ in dictionaries:
            if os.path.isfile(dict_):
                dictionary = dict_
                break

        # if we don't have a valid dictionary file, we exit
        if not dictionary:
            parser_error('No valid dictionary files have been specified or found within the tool')
             

        dict_type = 'user' if args.dictionary == dictionary else 'tool'
        print(f'Using the dictionary file: {dictionary} (provided by {dict_type})')

    request_timeout = float(args.lifetime)

    output_file = args.xml
    results_db = args.db
    csv_file = args.csv
    json_file = args.json

    # this flag summarizes if the program has to output
    do_output = bool(output_file or results_db or csv_file or json_file)

    verbose = args.verbose
    ignore_wildcardrr = args.iw
    CONFIG['disable_check_recursion'] = args.disable_check_recursion
    CONFIG['disable_check_bindversion'] = args.disable_check_bindversion

    xfr = args.a
    bing = False
    yandex = False
    do_crt = args.k
    do_whois = args.w
    zonewalk = args.z
    spf_enum = args.s 
    wildcard_filter = args.f
    proto = 'tcp' if args.tcp else 'udp'

    # Set the resolver
    res = DnsHelper(domain, ns_server, request_timeout, proto)

    scan_info = [' '.join(sys.argv), str(datetime.datetime.now())]



    banner()



    # Sublist3r

    # print(B + "Running Sublist3r ")
    # subdomains = sublist3r(domain, threads, savefile, silent=False, verbose=verbose, enable_bruteforce=enable_bruteforce)
    # print(subdomains)

    # dnsrecon
    print(B + "Running dnsrecon ")
    smth = dnsrecon(domain, types, type_map, res, request_timeout, do_output, rvl_ip_list, dictionary, ns_server, scan_info, xfr, bing, yandex, spf_enum, do_whois, do_crt, zonewalk, verbose, wildcard_filter, ignore_wildcardrr, output_file, results_db, json_file, csv_file, threads)
    print(smth)
