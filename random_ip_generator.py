"""
Author: Emily Gao
Purpose: Originally developed to pick a random address to spoof for a Network Security course project, this program has been extended to easily allow the generation of a random IP from specified IP ranges.
Without input, this program will return an IP from Unallocated (Free) Address Space as defined by the Bogon Report https://www.cidr-report.org/bogons/
"""
import argparse, requests, ipaddress, os, random, socket, struct

def retrieve_ips(public=True):
    """
    :public: boolean, if true the allow_list will be all unallocated public address space, otherwise it will be all allocated public and private address space
    """
    ipv4_space = "freespace-prefix.txt" if public else "allocspace-prefix.txt"
    response = requests.get(f"https://www.cidr-report.org/bogons/{ipv4_space}")
    if response.status_code == 200:
        with open(f"{os.getcwd()}/ip_gen_files/{ipv4_space}", "w") as outfile: # update this whenever a new list is avail, since bogons list updates
            outfile.write(response.text)
    # if an updated list can be pulled, great! now read from file just written. if not, no worries, read from old file cached from last success (earliest success from 04/24/2023)
    with open(f"{os.getcwd()}/ip_gen_files/{ipv4_space}", "r") as infile:
        list_ips = infile.readlines()
    return list_ips

def random_ip_generator(allow_list):
    """
    :allow_list: list of CIDR ranges, this program will randomly select one range out of the list and randomly select one IP from that range
    """
    default_range = allow_list[random.randint(0, len(allow_list)-1)].strip() # randomly select one default range from a list of CIDR ranges for unallocated public IP space
    (net, cidr) = default_range.split('/')
    
    # calculates valid IP range
    setbits = 32 - int(cidr)
    usbi = socket.inet_aton(net)
    lower = struct.unpack('!I', usbi)[0]
    higher = lower + 2**setbits

    address = ipaddress.IPv4Address(random.randint(lower, higher))
    return address

def main(args):
    if args.priv:
        print(random_ip_generator(retrieve_ips(False)))
    else:
        if args.range:
            print(random_ip_generator([args.range]))
        else:
            print(random_ip_generator(retrieve_ips()))

if __name__ == "__main__":
    help_text = '''examples:\npython3 random_ip_generator.py\npython3 random_ip_generator.py -p\npython3 random_ip_generator.py -r 15.0.0.0/8'''
    parser = argparse.ArgumentParser(prog="random_ip_generator", epilog=help_text, description="Random IP Generator", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-r", "--range", default=None, help="CIDR range to randomly pick IP from. If not specified, range will be set to a random public IP range.")
    parser.add_argument("-p", "--priv", action="store_true", help="If specified, range will be set to a random unallocated (public or private) IP range.")
    args = parser.parse_args()
    main(args)