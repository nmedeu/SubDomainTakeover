#!/usr/bin/env python3

#    DNSRecon
#
#    Copyright (C) 2023 Carlos Perez
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; Applies version 2 of the License.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#    See the GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

import datetime
import json
import os
from argparse import ArgumentParser, RawTextHelpFormatter
from concurrent import futures
from random import SystemRandom
from string import ascii_letters, digits
import re

import dns.flags
import dns.message
import dns.query
import dns.rdata
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone
import netaddr
from dns.dnssec import algorithm_to_text
from numpy import unique

from dnshelper import DnsHelper
from msf_print import *
from tlds import TLDS
from whois import *

# Global Variables for Brute force Threads
brtdata = []


# Function Definitions
# -------------------------------------------------------------------------------


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
                ip_list.append(netaddr.IPNetwork(entry))

            elif re.match(r'\S*-\S*', entry):
                range_vals.extend(entry.split('-'))
                if len(range_vals) == 2:
                    ip_list.append(netaddr.IPRange(range_vals[0], range_vals[1]))
            else:
                print_error(f'Range: {entry} provided is not valid')
        except Exception:
            print(Exception)
            print_error(f'Range: {entry} provided is not valid')

    return ip_list


def process_spf_data(res, data):
    """
    This function will take the text info of a TXT or SPF record, extract the
    IPv4, IPv6 addresses and ranges, a request process includes records and returns
    a list of IP Addresses for the records specified in the SPF Record.
    """
    # Declare lists that will be used in the function.
    ipv4 = []
    ipv6 = []
    includes = []
    ip_list = []

    # check first if it is a sfp record
    if not re.search(r'v=spf', data):
        return

    # Parse the record for IPv4 Ranges, individual IPs and include TXT Records.
    ipv4.extend(re.findall(r'ip4:(\S*)', ''.join(data)))
    ipv6.extend(re.findall(r'ip6:(\S*)', ''.join(data)))

    # Create a list of IPNetwork objects.
    for ip in ipv4:
        for i in netaddr.IPNetwork(ip):
            ip_list.append(i)

    for ip in ipv6:
        for i in netaddr.IPNetwork(ip):
            ip_list.append(i)

    # Extract and process include values.
    includes.extend(re.findall(r'include:(\S*)', ''.join(data)))
    for inc_ranges in includes:
        for spr_rec in res.get_txt(inc_ranges):
            spf_data = process_spf_data(res, spr_rec[2])
            if spf_data is not None:
                ip_list.extend(spf_data)

    # Return a list of IP Addresses
    return [str(ip) for ip in ip_list]


def expand_cidr(cidr_to_expand):
    """
    Function to expand a given CIDR and return an Array of IP Addresses that
    form the range covered by the CIDR.
    """
    return netaddr.IPNetwork(cidr_to_expand)


def expand_range(startip, endip):
    """
    Function to expand a given range and return an Array of IP Addresses that
    form the range.
    """
    return netaddr.IPRange(startip, endip)


def range2cidr(ip1, ip2):
    """
    Function to return the maximum CIDR given a range of IP's
    """
    r1 = netaddr.IPRange(ip1, ip2)
    return str(r1.cidrs()[-1])


def write_to_file(data, target_file):
    """
    Function for writing returned data to a file
    """
    with open(target_file, 'w') as fd:
        fd.write(data)


def generate_testname(name_len, name_suffix):
    """
    This function easily allows generating a testname
    to be used within the wildcard resolution and
    the NXDOMAIN hijacking checks
    """
    testname = SystemRandom().sample(ascii_letters + digits, name_len)
    return ''.join(testname) + '.' + name_suffix


def check_wildcard(res, domain_trg):
    """
    Function for checking if Wildcard resolution is configured for a Domain
    """
    testname = generate_testname(12, domain_trg)

    ips = res.get_a(testname)
    if not ips:
        return None

    wildcard_set = set()
    print_debug('Wildcard resolution is enabled on this domain')
    for ip in ips:
        print_debug(f'It is resolving to {ip[2]}')
        wildcard_set.add(ip[2])
    print_debug('All queries will resolve to this list of addresses!!')
    return wildcard_set


def brute_reverse(res, ip_list, verbose=False, thread_num=None):
    """
    Reverse look-up brute force for given CIDR example 192.168.1.1/24. Returns an
    Array of found records.
    """
    global brtdata
    brtdata = []
    returned_records = []

    for i in range(len(ip_list)):
        start_ip = ip_list[i][0]
        end_ip = ip_list[i][-1]
        print_status(f'Performing Reverse Lookup from {start_ip} to {end_ip}')

        # Resolve each IP in a separate thread in groups of 255 hosts.

        ip_range = range(len(ip_list[i]) - 1)
        ip_group_size = 255
        for ip_group in [ip_range[j : j + ip_group_size] for j in range(0, len(ip_range), ip_group_size)]:
            try:
                if verbose:
                    for x in ip_group:
                        ipaddress = str(ip_list[x])
                        print_status(f'Trying {ipaddress}')

                with futures.ThreadPoolExecutor(max_workers=thread_num) as executor:
                    future_results = {executor.submit(res.get_ptr, str(ip_list[i][x])): x for x in ip_group}
                    # Display logs as soon as a thread is finished
                    for future in futures.as_completed(future_results):
                        res_ = future.result()
                        for type_, name_, addr_ in res_:
                            returned_records.append([{'type': type_, 'name': name_, 'address': addr_}])
                            print_good(f'\t {type_} {name_} {addr_}')

            except Exception as e:
                print_error(e)

    print_good(f'{len(returned_records)} Records Found')
    return returned_records


def se_result_process(res, se_entries):
    """
    This function processes the results returned from a Search Engine and does
    an A and AAAA query for the IP of the found host. Prints and returns a dictionary
    with all the results found.
    """
    if not se_entries:
        return None

    resolved_se_entries = []
    for se_entry in se_entries:
        for type_, name_, address_or_target_ in res.get_ip(se_entry):
            if type_ not in ['A', 'CNAME']:
                continue

            print_status(f'\t {type_} {name_} {address_or_target_}')
            resolved_se_entry = {'type': type_, 'name': name_}

            if type_ == 'A':
                resolved_se_entry['address'] = address_or_target_
            elif type_ == 'CNAME':
                resolved_se_entry['target'] = address_or_target_

            resolved_se_entries.append(resolved_se_entry)

    print_good(f'{len(resolved_se_entries)} Records Found')
    return resolved_se_entries


def get_whois_nets_iplist(ip_list):
    """
    This function will perform whois queries against a list of IP's and extract
    the net ranges and if available the organization list of each and remover any
    duplicate entries.
    """
    seen = {}
    idfun = repr
    found_nets = []
    for ip in ip_list:
        if ip != 'no_ip':
            # Find appropriate Whois Server for the IP
            whois_server = get_whois(ip)
            # If we get a Whois server Process get the whois and process.
            if whois_server:
                whois_data = whois(ip, whois_server)
                arin_style = re.search('NetRange', whois_data)
                ripe_apic_style = re.search('netname', whois_data)
                if arin_style or ripe_apic_style:
                    net = get_whois_nets(whois_data)
                    if net:
                        for network in net:
                            org = get_whois_orgname(whois_data)
                            found_nets.append(
                                {
                                    'start': network[0],
                                    'end': network[1],
                                    'orgname': ''.join(org),
                                }
                            )
                else:
                    for line in whois_data.splitlines():
                        recordentrie = re.match(r'^(.*)\s\S*-\w*\s\S*\s(\S*\s-\s\S*)', line)
                        if recordentrie:
                            org = recordentrie.group(1)
                            net = get_whois_nets(recordentrie.group(2))
                            for network in net:
                                found_nets.append(
                                    {
                                        'start': network[0],
                                        'end': network[1],
                                        'orgname': ''.join(org),
                                    }
                                )
    # Remove Duplicates
    return [seen.setdefault(idfun(e), e) for e in found_nets if idfun(e) not in seen]


def whois_ips(res, ip_list):
    """
    This function will process the results of the whois lookups and present the
    user with the list of net ranges found and ask the user if he wishes to perform
    a reverse lookup on any of the ranges or all the ranges.
    """
    found_records = []
    print_status('Performing Whois lookup against records found.')
    list_whois = get_whois_nets_iplist(unique(ip_list))
    if len(list_whois) > 0:
        print_status('The following IP Ranges were found:')
        for i in range(len(list_whois)):
            print_status(
                '\t {0} {1}-{2} {3}'.format(
                    str(i) + ')',
                    list_whois[i]['start'],
                    list_whois[i]['end'],
                    list_whois[i]['orgname'],
                )
            )
        print_status('What Range do you wish to do a Reverse Lookup for?')
        print_status('number, comma separated list, a for all or n for none')
        val = sys.stdin.readline()[:-1]
        answer = str(val).split(',')

        if 'a' in answer:
            for i in range(len(list_whois)):
                print_status('Performing Reverse Lookup of range {0}-{1}'.format(list_whois[i]['start'], list_whois[i]['end']))
                found_records.append(brute_reverse(res, expand_range(list_whois[i]['start'], list_whois[i]['end'])))

        elif 'n' in answer:
            print_status('No Reverse Lookups will be performed.')
        else:
            for a in answer:
                net_selected = list_whois[int(a)]
                print_status(net_selected['orgname'])
                print_status('Performing Reverse Lookup of range {0}-{1}'.format(net_selected['start'], net_selected['end']))
                found_records.append(brute_reverse(res, expand_range(net_selected['start'], net_selected['end'])))
    else:
        print_error('No IP Ranges were found in the Whois query results')

    return found_records

def make_csv(data):
    csv_data = 'Type,Name,Address,Target,Port,String\n'
    for record_tmp in data:
        record = record_tmp
        # make sure that we are working with a dictionary.
        if not isinstance(record, dict):
            # the representation of data[i] is a list of one dictionary
            # we want to exploit this dictionary
            record = record_tmp[0]

        type_ = record['type'].upper()
        csv_data += type_ + ','

        if type_ in ['PTR', 'A', 'AAAA', 'NS', 'SOA', 'MX']:
            if type_ in ['PTR', 'A', 'AAAA']:
                csv_data += record['name']
            elif type_ == 'NS':
                csv_data += record['target']
            elif type_ == 'SOA':
                csv_data += record['mname']
            elif type_ == 'MX':
                csv_data += record['exchange']

            csv_data += ',' + record['address'] + (',' * 3) + '\n'

        elif type_ in ['TXT', 'SPF']:
            if 'zone_server' not in record:
                if type_ == 'SPF':
                    csv_data += record['domain']
                else:
                    csv_data += record['name']

            csv_data += (',' * 4) + "'{}'\n".format(record['strings'])

        elif type_ == 'SRV':
            items = [
                record['name'],
                record['address'],
                record['target'],
                record['port'],
            ]
            csv_data += ','.join(items) + ',\n'

        elif type_ == 'CNAME':
            csv_data += record['name'] + (',' * 2)
            if 'target' in record:
                csv_data += record['target']

            csv_data += (',' * 2) + '\n'

        else:
            # Handle not common records
            del record['type']
            s = '; '.join([f'{k}={v}' for k, v in record.items()])
            csv_data += (',' * 4) + f"'{s}'\n"

    return csv_data


def write_json(jsonfile, data, scan_info):
    """
    Function to write DNS Records SOA, PTR, NS, A, AAAA, MX, TXT, SPF and SRV to
    JSON file.
    """
    scaninfo = {'type': 'ScanInfo', 'arguments': scan_info[0], 'date': scan_info[1]}
    data.insert(0, scaninfo)
    json_data = json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))
    write_to_file(json_data, jsonfile)


def get_nsec_type(domain, res):
    target = '0.' + domain

    answer = get_a_answer(res, target, res._res.nameservers[0], res._res.timeout)
    for a in answer.authority:
        if a.rdtype == 50:
            return 'NSEC3'
        elif a.rdtype == 47:
            return 'NSEC'


def dns_sec_check(domain, res):
    """
    Check if a zone is configured for DNSSEC and if so is NSEC or NSEC3 is used.
    """
    try:
        answer = res.resolve(domain, 'DNSKEY', res._res.nameservers[0])
        print_status(f'DNSSEC is configured for {domain}')
        nsectype = get_nsec_type(domain, res)
        print_status('DNSKEYs:')
        for rdata in answer:
            if rdata.flags == 256:
                key_type = 'ZSK'

            if rdata.flags == 257:
                key_type = 'KSk'

            print_status(f'\t{nsectype} {key_type} {algorithm_to_text(rdata.algorithm)} {dns.rdata._hexify(rdata.key)}')

    except dns.resolver.NXDOMAIN:
        print_error(f'Could not resolve domain: {domain}')
        sys.exit(1)

    except dns.resolver.NoNameservers:
        print_error(f'All nameservers failed to answer the DNSSEC query for {domain}')

    except dns.exception.Timeout:
        print_error('A timeout error occurred please make sure you can reach the target DNS Servers')
        print_error(f'directly and requests are not being filtered. Increase the timeout from {res._res.timeout} second')
        print_error('to a higher number with --lifetime <time> option.')
        sys.exit(1)
    except dns.resolver.NoAnswer:
        print_error(f'DNSSEC is not configured for {domain}')


def general_enum(
    res,
    domain,
    do_axfr,
    do_spf,
    do_whois,
    zw,
    request_timeout,
    thread_num=None,
):
    """
    Function for performing general enumeration of a domain. It gets SOA, NS, MX
    A, AAAA and SRV records for a given domain. It will first try a Zone Transfer
    if not successful, it will try individual record type enumeration.
    """
    returned_records = []

    # Var for SPF Record Range Reverse Look-up
    found_spf_ranges = []

    # Var to hold the IP Addresses that will be queried in Whois
    ip_for_whois = []

    # Check if wildcards are enabled on the target domain
    check_wildcard(res, domain)

    # To identify when the records come from a Zone Transfer
    from_zt = None

    # Perform test for Zone Transfer against all NS servers of a Domain
    if do_axfr:
        zonerecs = res.zone_transfer()
        if zonerecs is not None:
            returned_records.extend(res.zone_transfer())
            if len(returned_records) == 0:
                from_zt = True

    # If a Zone Transfer was possible there is no need to enumerate the rest
    if from_zt is None:
        # Check if DNSSEC is configured
        dns_sec_check(domain, res)

        # Enumerate SOA Record
        try:
            found_soa_records = res.get_soa()
            for found_soa_record in found_soa_records:
                print_status(f'\t {found_soa_record[0]} {found_soa_record[1]} {found_soa_record[2]}')

                # Save dictionary of returned record
                returned_records.extend(
                    [
                        {
                            'domain': domain,
                            'type': found_soa_record[0],
                            'mname': found_soa_record[1],
                            'address': found_soa_record[2],
                        }
                    ]
                )

                ip_for_whois.append(found_soa_record[2])

        except Exception:
            print(found_soa_records)
            if found_soa_records == []:
                print_error(f'No SOA records found for {domain}')
            else:
                print_error(f'Could not Resolve SOA Record for {domain}')

        # Enumerate Name Servers
        try:
            for ns_rcrd in res.get_ns():
                print_status(f'\t {ns_rcrd[0]} {ns_rcrd[1]} {ns_rcrd[2]}')

                # Save dictionary of returned record
                returned_records.extend(
                    [
                        {
                            'domain': domain,
                            'type': ns_rcrd[0],
                            'target': ns_rcrd[1],
                            'address': ns_rcrd[2],
                        }
                    ]
                )
                ip_for_whois.append(ns_rcrd[2])

        except dns.resolver.NoAnswer:
            print_error(f'Could not Resolve NS Records for {domain}')
        except dns.resolver.NoNameservers:
            print_error(f'All nameservers failed to answer the NS query for {domain}')
            sys.exit(1)

        # Enumerate MX Records
        try:
            for mx_rcrd in res.get_mx():
                print_status(f'\t {mx_rcrd[0]} {mx_rcrd[1]} {mx_rcrd[2]}')

                # Save dictionary of returned record
                returned_records.extend(
                    [
                        {
                            'domain': domain,
                            'type': mx_rcrd[0],
                            'exchange': mx_rcrd[1],
                            'address': mx_rcrd[2],
                        }
                    ]
                )

                ip_for_whois.append(mx_rcrd[2])

        except dns.resolver.NoAnswer:
            print_error(f'Could not Resolve MX Records for {domain}')
        except dns.resolver.NoNameservers:
            print_error(f'All nameservers failed to answer the MX query for {domain}')

        # Enumerate A Record for the targeted Domain
        for a_rcrd in res.get_ip(domain):
            print_status(f'\t {a_rcrd[0]} {a_rcrd[1]} {a_rcrd[2]}')

            # Save dictionary of returned record
            returned_records.extend(
                [
                    {
                        'domain': domain,
                        'type': a_rcrd[0],
                        'name': a_rcrd[1],
                        'address': a_rcrd[2],
                    }
                ]
            )

            ip_for_whois.append(a_rcrd[2])

        # Enumerate SFP and TXT Records for the target domain
        text_data = ''
        spf_text_data = res.get_spf()

        # Save dictionary of returned record
        if spf_text_data is not None:
            for s in spf_text_data:
                print_status(f'\t {s[0]} {s[1]}')
                text_data = s[1]
                returned_records.extend([{'domain': domain, 'type': s[0], 'strings': s[1]}])

        txt_text_data = res.get_txt()

        # Save dictionary of returned record
        if txt_text_data is not None:
            for t in txt_text_data:
                print_status(f'\t {t[0]} {t[1]} {t[2]}')
                text_data += t[2]
                returned_records.extend([{'domain': domain, 'type': t[0], 'name': t[1], 'strings': t[2]}])

        domainkey_text_data = res.get_txt('_domainkey.' + domain)

        # Save dictionary of returned record
        if domainkey_text_data is not None:
            for t in domainkey_text_data:
                print_status(f'\t {t[0]} {t[1]} {t[2]}')
                text_data += t[2]
                returned_records.extend([{'domain': domain, 'type': t[0], 'name': t[1], 'strings': t[2]}])

        # Process SPF records if selected
        if do_spf and len(text_data) > 0:
            print_status('Expanding IP ranges found in DNS and TXT records for Reverse Look-up')
            processed_spf_data = process_spf_data(res, text_data)
            if processed_spf_data is not None:
                found_spf_ranges.extend(processed_spf_data)
            if len(found_spf_ranges) > 0:
                print_status('Performing Reverse Look-up of SPF Ranges')
                returned_records.extend(brute_reverse(res, unique(found_spf_ranges)))
            else:
                print_status('No IP Ranges were found in SPF and TXT Records')

        if do_whois:
            whois_rcd = whois_ips(res, ip_for_whois)
            if whois_rcd:
                for r in whois_rcd:
                    returned_records.extend(r)

        if zw:
            zone_info = ds_zone_walk(res, domain, request_timeout)
            if zone_info:
                returned_records.extend(zone_info)

        return returned_records


def query_ds(res, target, ns, timeout=5.0):
    """
    Function for performing DS Record queries. Returns answer object. Since a
    timeout will break the DS NSEC chain of a zone walk, it will exit if a timeout
    happens.
    """
    try:
        query = dns.message.make_query(target, dns.rdatatype.DS, dns.rdataclass.IN)
        query.flags += dns.flags.CD
        query.use_edns(edns=True, payload=4096)
        query.want_dnssec(True)
        answer = res.query(query, ns, timeout)
    except dns.exception.Timeout:
        print_error('A timeout error occurred please make sure you can reach the target DNS Servers')
        print_error(f'directly and requests are not being filtered. Increase the timeout from {timeout} second')
        print_error('to a higher number with --lifetime <time> option.')
        sys.exit(1)
    except Exception:
        print(f'Unexpected error: {sys.exc_info()[0]}')
        raise
    return answer


def get_constants(prefix):
    """
    Create a dictionary mapping socket module constants to their names.
    """
    return dict((getattr(socket, n), n) for n in dir(socket) if n.startswith(prefix))


def socket_resolv(target):
    """
    Resolve IPv4 and IPv6 .
    """
    found_recs = []
    families = get_constants('AF_')
    types = get_constants('SOCK_')
    try:
        for response in socket.getaddrinfo(target, 0):
            # Unpack the response tuple
            family, socktype, proto, canonname, sockaddr = response
            if families[family] == 'AF_INET' and types[socktype] == 'SOCK_DGRAM':
                found_recs.append(['A', target, sockaddr[0]])
            elif families[family] == 'AF_INET6' and types[socktype] == 'SOCK_DGRAM':
                found_recs.append(['AAAA', target, sockaddr[0]])
    except Exception:
        return found_recs
    return found_recs


def lookup_next(target, res):
    """
    Try to get the most accurate information for the record found.
    """
    DnsHelper(target)
    returned_records = []

    if re.search(r'(_autodiscover\\.|_spf\\.|_domainkey\\.)', target, re.I):
        txt_answer = res.get_txt(target)
        if len(txt_answer) > 0:
            for r in txt_answer:
                print_status('\t {0}'.format(' '.join(r)))
                returned_records.append({'type': r[0], 'name': r[1], 'strings': r[2]})
        else:
            txt_answer = res.get_txt(target)
            if len(txt_answer) > 0:
                for r in txt_answer:
                    print_status('\t {0}'.format(' '.join(r)))
                    returned_records.append({'type': r[0], 'name': r[1], 'strings': r[2]})
            else:
                print_status(f'\t A {target} no_ip')
                returned_records.append({'type': 'A', 'name': target, 'address': 'no_ip'})

    else:
        a_answer = res.get_ip(target)
        if len(a_answer) > 0:
            for r in a_answer:
                print_status(f'\t {r[0]} {r[1]} {r[2]}')
                if r[0] == 'CNAME':
                    returned_records.append({'type': r[0], 'name': r[1], 'target': r[2]})
                else:
                    returned_records.append({'type': r[0], 'name': r[1], 'address': r[2]})
        else:
            a_answer = socket_resolv(target)
            if len(a_answer) > 0:
                for r in a_answer:
                    print_status(f'\t {r[0]} {r[1]} {r[2]}')
                    returned_records.append({'type': r[0], 'name': r[1], 'address': r[2]})
            else:
                print_status(f'\t A {target} no_ip')
                returned_records.append({'type': 'A', 'name': target, 'address': 'no_ip'})

    return returned_records


def get_a_answer(res, target, ns, timeout):
    query = dns.message.make_query(target, dns.rdatatype.A, dns.rdataclass.IN)
    query.flags += dns.flags.CD
    query.use_edns(edns=True, payload=4096)
    query.want_dnssec(True)
    answer = res.query(query, ns, timeout)
    return answer


def get_next(res, target, ns, timeout):
    next_host = None
    response = get_a_answer(res, target, ns, timeout)
    for a in response.authority:
        if a.rdtype == 47:
            for r in a:
                next_host = r.next.to_text()[:-1]
    return next_host


def ds_zone_walk(res, domain, lifetime):
    """
    Perform DNSSEC Zone Walk using NSEC records found in the error an additional
    records section of the message to find the next host to query in the zone.
    """
    print_status(f'Performing NSEC Zone Walk for {domain}')
    print_status(f'Getting SOA record for {domain}')

    nameserver = ''

    try:
        # Get the list of SOA servers, should be a list of lists
        target_soas = res.get_soa()
        if target_soas:
            first_ns = target_soas[0]
            # The 3rd value is the SOA's IP address
            if first_ns:
                nameserver = first_ns[2]

                if nameserver:
                    # At this point, we should have a name server IP in 'nameserver'
                    print_status(f'Name Server {nameserver} will be used')
                    res = DnsHelper(domain, nameserver, lifetime)

        if not nameserver:
            print_error('This zone appears to be misconfigured, no SOA record found.')

    except Exception as err:
        print_error(f'Exception while trying to determine the SOA records for domain {domain}: {err}')

    timeout = res._res.timeout

    records = []

    transformations = [
        # Send the hostname as-is
        lambda h, hc, dc: h,
        # Prepend a zero as a subdomain
        lambda h, hc, dc: f'0.{h}',
        # Append a hyphen to the host portion
        lambda h, hc, dc: f'{hc}-.{dc}' if hc else None,
        # Double the last character of the host portion
        lambda h, hc, dc: f'{hc}{hc[-1]}.{dc}' if hc else None,
    ]

    pending = {domain}
    finished = set()

    try:
        while pending:
            # Get the next pending hostname
            hostname = pending.pop()
            finished.add(hostname)

            # Get all the records we can for the hostname
            records.extend(lookup_next(hostname, res))

            # Arrange the arguments for the transformations
            fields = re.search(r'^(^[^.]*)\.(\S+\.\S*)$', hostname)

            domain_portion = hostname
            if fields and fields.group(2):
                domain_portion = fields.group(2)

            host_portion = ''
            if fields and fields.group(1):
                host_portion = fields.group(1)

            params = [hostname, host_portion, domain_portion]

            walk_filter = '.' + domain_portion
            walk_filter_offset = len(walk_filter) + 1

            for transformation in transformations:
                # Apply the transformation
                target = transformation(*params)
                if not target:
                    continue

                # Perform a DNS query for the target and process the response
                if not nameserver:
                    response = get_a_answer(res, target, res._res.nameservers[0], timeout)
                else:
                    response = get_a_answer(res, target, nameserver, timeout)
                for a in response.authority:
                    if a.rdtype != 47:
                        continue

                    # NSEC records give two results:
                    #   1) The previous existing hostname that is signed
                    #   2) The subsequent existing hostname that is signed
                    # Add the latter to our list of pending hostnames
                    for r in a:
                        # As an optimization Cloudflare (and perhaps others)
                        # return '\000.' instead of NODATA when a record doesn't
                        # exist. Detect this and avoid becoming tarpitted while
                        # permuting the namespace.
                        if r.next.to_text()[:5] == '\\000.':
                            continue

                        # Avoid walking outside of the target domain. This
                        # happens with certain misconfigured domains.
                        if r.next.to_text()[-walk_filter_offset:-1] == walk_filter:
                            pending.add(r.next.to_text()[:-1])

            # Ensure nothing pending has already been queried
            pending -= finished

    except KeyboardInterrupt:
        print_error('You have pressed Ctrl + C. Saving found records.')

    except dns.exception.Timeout:
        print_error('A timeout error occurred while performing the zone walk please make ')
        print_error('sure you can reach the target DNS Servers directly and requests')
        print_error('are not being filtered. Increase the timeout to a higher number')
        print_error('with --lifetime <time> option.')

    except EOFError:
        print_error(f'SoA nameserver {nameserver} failed to answer the DNSSEC query for {target}')

    except socket.error:
        print_error(f'SoA nameserver {nameserver} failed to answer the DNSSEC query for {domain}')

    # Give a summary of the walk
    if len(records) > 0:
        print_good(f'{len(records)} records found')
    else:
        print_error('Zone could not be walked')

    return records


def main(types):

    # we have finished to validate params,
    # we can start the execution
    for type_ in types:

        try:
            # here we start checking for the different types
            if type_ == 'axfr':
                zonercds = res.zone_transfer()
                if not zonercds:
                    print_error(f'{type_}: No records were returned.')
                    continue

                returned_records.extend(zonercds)

            elif type_ == 'std':
                print_status(f'{type_}: Performing General Enumeration against: {domain}...')
                std_enum_records = general_enum(
                    res,
                    domain,
                    xfr,
                    spf_enum,
                    do_whois,
                    zonewalk,
                    request_timeout,
                    thread_num=thread_num,
                )
                if do_output and std_enum_records:
                    returned_records.extend(std_enum_records)

            elif type_ == 'brt':
                # here we are ready to perform the bruteforce
                print_status(f'{type_}: Performing host and subdomain brute force against {domain}...')
                brt_enum_records = brute_domain(
                    res,
                    dictionary,
                    domain,
                    wildcard_filter,
                    verbose,
                    ignore_wildcardrr,
                    thread_num=thread_num,
                )
                if do_output and brt_enum_records:
                    returned_records.extend(brt_enum_records)

            elif type_ == 'tld':
                print_status(f'{type_}: Performing TLD Brute force Enumeration against {domain}...')
                tld_enum_records = brute_tlds(res, domain, verbose, thread_num=thread_num)
                if do_output:
                    returned_records.extend(tld_enum_records)

            elif type_ == 'zonewalk':
                zonewalk_result = ds_zone_walk(res, domain, request_timeout)
                if do_output:
                    returned_records.extend(zonewalk_result)

            else:
                print_error(f'{type_}: This type of scan is not in the list.')

        except dns.resolver.NXDOMAIN:
            print_error(f'Could not resolve domain: {domain}')
            sys.exit(1)

        except dns.exception.Timeout:
            print_error(
                f"""A timeout error occurred.
Please make sure you can reach the target DNS Servers directly and requests are not being filtered.
Increase the timeout from {request_timeout} seconds to a higher number with --lifetime <time> option."""
            )
            sys.exit(1)

    # if the program has not exited,
    # we can check if output is needed

    # if an output csv file is specified, it will write returned results.
    if csv_file:
        print_status(f'Saving records to CSV file: {csv_file}')
        write_to_file(make_csv(returned_records), csv_file)

    # if an output json file is specified, it will write returned results.
    if json_file:
        print_status(f'Saving records to JSON file: {json_file}')
        write_json(json_file, returned_records, scan_info)

    sys.exit(0)