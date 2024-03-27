# Standard Lib Modules
import sys
import argparse
import re
import os

# External Modules
from .subdomain_enum.sublist3r import sublist3r

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


# Define Args
def parse_args():
    # parse the arguments

    # sublist3r args
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -d google.com")
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    parser.add_argument('-d', '--domain', help="Target Domain", required=True)
    parser.add_argument('-b', '--bruteforce', help='Enable the subbrute bruteforce module', nargs='?', default=False)
    parser.add_argument('-v', '--verbose', help='Enable Verbosity and display results in realtime', nargs='?', default=False)
    parser.add_argument('-t', '--threads', help='Number of threads to use for subbrute bruteforce', type=int, default=30)
    parser.add_argument('-o', '--output', help='Save the results to text file')
    parser.add_argument('-n', '--no-color', help='Output without color', default=False, action='store_true')

    # dnsrecon args
    parser.add_argument('-l', '--lifetime', help='Time to wait for a server to respond to a query. default is 3.0', type=float, dest='lifetime', default=3.0)
    parser.add_argument('-c', '--csv', help='Save output to a comma separated value file.', type=str, dest='csv')
    parser.add_argument('-j', '--json', type=str, dest='json', help='save output to a JSON file.')
    parser.add_argument('-z', '--zonewalk', help='Performs a DNSSEC zone walk with standard enumeration.', default=True, action='store_true')
    parser.add_argument(
            '-D',
            '--dictionary',
            type=str,
            dest='dictionary',
            help='Dictionary file of subdomain and hostnames to use for brute force.',
        )
    parser.add_argument(
            '-T',
            '--type',
            type=str,
            dest='type',
            help="""Type of enumeration to perform.
                        Possible types:
                            std:      SOA, NS, A, AAAA, MX and SRV.
                            brt:      Brute force domains and hosts using a given dictionary.
                            axfr:     Test all NS servers for a zone transfer.
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
    savefile = args.output
    enable_bruteforce = args.bruteforce
    verbose = args.verbose
    lifetime = args.lifetime
    csv = args.csv
    json = args.json
    zonewalk = args.zonewalk
    
    # a "map" that specifies if a type of scan needs
    # the domain and the dictionary
    type_map = {
        'axfr': {'domain': True, 'dictionary': False},
        'std': {'domain': True, 'dictionary': False},
        'tld': {'domain': True, 'dictionary': False},
        'zonewalk': {'domain': True, 'dictionary': False},
        'brt': {'domain': True, 'dictionary': True},
    }
    valid_types = type_map.keys()

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

    
    else:
        types=['std', 'brt', 'axfr', 'tld', 'zonewalk']


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

    if args.threads:
        thread_num = int(args.threads)

    request_timeout = float(args.lifetime)

    csv_file = args.csv
    json_file = args.json

        # this flag summarizes if the program has to output
    do_output = bool(output_file or results_db or csv_file or json_file)

    verbose = arguments.verbose
    ignore_wildcardrr = arguments.iw
    CONFIG['disable_check_recursion'] = arguments.disable_check_recursion
    CONFIG['disable_check_bindversion'] = arguments.disable_check_bindversion

    xfr = arguments.a
    do_whois = arguments.w
    zonewalk = arguments.z
    spf_enum = arguments.s
    wildcard_filter = arguments.f
    proto = 'tcp' if arguments.tcp else 'udp'

    # Set the resolver
    res = DnsHelper(domain, ns_server, request_timeout, proto)

    scan_info = [' '.join(sys.argv), str(datetime.datetime.now())]


    if verbose or verbose is None:
        verbose = True
    if args.no_color:
        no_color()
    banner()
    # Sublist3r

    print(B + "Running Sublist3r ")
    subdomains = sublist3r(domain, threads, savefile, silent=False, verbose=verbose, enable_bruteforce=enable_bruteforce)

    # dnsrecon
    