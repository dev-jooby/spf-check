#!/usr/bin/env python3
# Last update - 31/05/2023
import sys
import dns.resolver
import spf
import re
import argparse

# Colouring
class bcolours:
    YELLOW = "\033[93m"
    ENDC = "\033[0m"

parser = argparse.ArgumentParser(
    prog='spf-check',
    description=
    '''
      Validates that the SPF record on the supplied domain is 
      syntatically correct and below the 10 lookup limit
    '''
  )

parser.add_argument('domain',
    help="- Specified domain to lookup"
  )

args = parser.parse_args(sys.argv[1:])

# Gets the SPF record from the provided domain name
def get_spf_record(domain):
    try:
        spf_records = dns.resolver.query(domain, 'TXT')
        for record in spf_records:
            if record.strings[0].startswith(b'v=spf1'): # We want only the records that start with "v=spf1"
                spf_record = record.strings[0].decode()
                break
        if not spf_record:
            return False, "\nNo SPF record found on the specified domain!\n"
        return True, spf_record  # Return the SPF record if found

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.resolver.NoNameservers):
        return False, "\nNo SPF record found on the specified domain!\n"

# Checks the SPF record and see's if it is valid
def check_spf_record(domain, ip_address, email):
    result = spf.check(i=ip_address, s=email, h=domain)
    return result

if __name__ == '__main__':
    ip_address = "10.0.0.1"
    email = f"test@{args.domain}"
    success, spf_record = get_spf_record(args.domain)
    if success:
        result = check_spf_record(args.domain, ip_address, email)
        if isinstance(result, tuple):
            spf_status, spf_code, spf_msg = result
            print(f"\n{bcolours.YELLOW}THE FOUND SPF RECORD IS:{bcolours.ENDC}")
            print(spf_record + "\n")
            # List for the strings I am specifically looking for - I dont give a fuck about any other ones
            # Uses regex to match only a specific section of the line
            error_msgs = [
                r'.*SPF Permanent Error: Invalid IP4 address:.*',
                r'.*SPF Permanent Error: Invalid IP6 address:.*',
                r'.*SPF Permanent Error: Unknown qualifier:.*',
                r'.*SPF Permanent Error: Unknown mechanism found:.*',
                r'.*SPF Permanent Error: empty domain:.*'
            ]
            if any(re.match(pattern, spf_msg) for pattern in error_msgs):
                print("The SPF record is not syntactically correct")
            else:
                print("The SPF record is syntactically correct")
            if re.match(r'.*SPF Permanent Error: Too many DNS lookups.*', spf_msg):
                print("The SPF record is over the 10 lookup limit\n")
            else:
                print("The SPF record is under the 10 lookup limit\n")
            if spf_code == 550 and spf_msg != "SPF fail - not authorized":
                print(f"{spf_msg}\n")
        else:
            print(result)
    else:
        print(spf_record)