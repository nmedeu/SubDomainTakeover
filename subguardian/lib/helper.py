from collections import defaultdict



def sort_records(records):

    records_by_type = defaultdict(list)

    for record in records:
        record_type = record.get('type')
        records_by_type[record_type].append(record)

    # Sorting the dictionary keys for easier reading
    sorted_records = {record_type: records for record_type, records in sorted(records_by_type.items())}

    return sorted_records


def unique_records(records):
    deduplicated_records = {}
    for record_type, entries in records.items():
        unique_entries_set = set(tuple(sorted(entry.items())) for entry in entries)
        deduplicated_records[record_type] = [dict(entry) for entry in unique_entries_set]
    return deduplicated_records

def add_sublist3r_if_cname_absent(records, subdomains):
    existing_cnames = {entry['name'] for entry in records.get('CNAME', [])}
    sublist3r_entries = []
    for subdomain in subdomains:
        if subdomain not in existing_cnames:
            sublist3r_entries.append({'name': subdomain, 'type': 'subdomain'})
    if 'sublist3r' in records:
        records['sublist3r'].extend(sublist3r_entries)
    else:
        records['sublist3r'] = sublist3r_entries
    return records


