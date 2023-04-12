import time
from datetime import datetime
from prettytable import PrettyTable
import itertools
import re
import nmap
import ipaddress
from scapy.all import *
import argparse
import socket
import concurrent.futures
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def style(text, style=0, fg_color=37, bg_color=40):
    """This function can style text using ANSI escape sequences.

    Styles:
        0: No effect
        1: Bold
        4: Underline
        7: Invert foreground and background colors

    Foreground Colors (30-37):
        30: Black
        31: Red
        32: Green
        33: Yellow
        34: Blue
        35: Magenta
        36: Cyan
        37: White

    Background Colors (40-47):
        40: Black
        41: Red
        42: Green
        43: Yellow
        44: Blue
        45: Magenta
        46: Cyan
        47: White

    Args:
        text (str): The string to be styled.
        style (int, optional):The 'style' type to apply. Defaults to 0 (No special style).
        fg_color (int, optional): The 'foreground color' to apply. Defaults to 37 (White).
        bg_color (int, optional): The 'background color' to apply. Defaults to 40 (Black).

    Returns:
        _type_: _description_
    """
    return f"\033[{style};{fg_color};{bg_color}m{text}\033[0m"


def discover_hosts(ip_range, workers=32):
    """This function starts the initial host discovery phase of the script.
     This function accepts both single IP's and lists. A certain amount of threads are created
     to proceed and check for a response by sending a TCP SYN packet.
     all 'live' hosts are returned as list of strings for use in other functions.

    Args:
        ip_range (str or list[strings]): A single IP or list of IP's in string format
        workers (int, optional): The amount of workers (threads) to discover hosts with. Defaults to 32.

    Returns:
        list[strings]: A list of live IP addresses formatted as strings.
    """
    toDiscover = len(ip_range)
    print(
        style(
            f"---[Live host discovery phase | {str(workers)} threads]---",
            7,
            33,
            40))
    print(style(f"Scanning {str(toDiscover)} host(s)...", 0, 33, 40))
    discovered = []

    def worker(ip):
        try:
            answer = sr1(IP(dst=str(ip)) /
                         TCP(dport=80, flags="S"), timeout=10, verbose=0)
            if answer:
                print(style(str(ip) + " is live!", 0, 33, 40))
                discovered.append(str(ip))
        except BaseException:
            print(
                style(
                    "ERROR: Something went wrong during host discovery, program execution will be continued however.",
                    0,
                    31,
                    40))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        executor.map(worker, ip_range)

    print(style("Found " +
                str(len(discovered)) +
                " live host(s) out of " +
                str(toDiscover), 0, 33, 40))
    return discovered


def discover_MAC(ip):
    """This function tries to discover the MAC address on a host on a local network.
    it does so by sending an ARP broadcast packet and analyzing the response.

    Args:
        ip (string): the host's IP address.

    Returns:
        string: The MAC address of the host.
    """
    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    answer, no_answer = srp(arp_packet, timeout=5, verbose=0)
    for request, response in answer:
        print(style("---[MAC Address]---", 1, 33, 40))
        print(style(f"MAC Address: {response[Ether].src}", 0, 33, 40))
        return str(response[Ether].src)


'''
These two variables are lists of the 100 and 25 most used TCP and UDP ports (respectively.)
The UDP ports are considerably less to save on scan time.
'''
mostCommonTCP = [
    20,
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    115,
    119,
    123,
    135,
    137,
    138,
    139,
    143,
    161,
    162,
    179,
    199,
    389,
    443,
    445,
    465,
    500,
    514,
    515,
    530,
    546,
    547,
    548,
    554,
    587,
    631,
    646,
    990,
    993,
    995,
    1080,
    1099,
    1194,
    1433,
    1521,
    1701,
    1723,
    1900,
    2049,
    2082,
    2083,
    2086,
    2087,
    2095,
    2096,
    3306,
    3389,
    5432,
    5060,
    5061,
    51413,
    5222,
    5223,
    5228,
    5900,
    5938,
    6000,
    8000,
    8008,
    8080,
    8443,
    8888,
    9000,
    9090,
    10000,
    10001,
    10010,
    10230,
    11371,
    12443,
    12975,
    17500,
    18080,
    19226,
    19810,
    20000,
    24444,
    24800,
    32400,
    32469,
    32764,
    34952,
    35000,
    35601,
    3689,
    3784,
    3826,
    4200,
    4711,
    4848,
    52869,
    54328]

mostCommonUDP = [
    7, 19, 53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 389,
    443, 445, 500, 514, 520, 631, 1900, 4500, 5353, 6000, 8080, 10000]


def discover_tcp_ports(ip, to_scan):
    """This function tries to find open TCP ports on a remote host
    by sending a 'SYN' packet to each provided port to the provided IP.

    If we receive a 'SYN ACK' we append the port to our found TCP ports.
    Otherwise we append it to our closed ports.

    Args:
        ip (string): The target ip as a string.
        to_scan (list): A list containing the TCP ports to be scanned.

    Returns:
        list, list: A list of open ports and a list of closed ports
    """

    foundOpen = []
    foundClosed = []

    print(
        style(
            f"---[Scanning for open TCP ports on host {ip}]---",
            1,
            33,
            40))
    for port in to_scan:
        answer = sr1(IP(dst=str(ip)) /
                     TCP(dport=int(port), flags="S"), timeout=5, verbose=0)
        if answer is not None:
            if answer[TCP].flags == "SA":
                print(style(f"TCP port {port} is open!", 0, 33, 40))
                foundOpen.append(str(port))
            else:
                foundClosed.append(str(port))
    if len(foundOpen) == 0:
        print(style(f"No open TCP ports found.", 0, 33, 40))
    return foundOpen, foundClosed


def discover_udp_ports(ip, to_scan=[]):
    """This function tries to find open UDP ports on a remote host
    by sending a UDP packet to each provided port to the provided IP.

    If we receive a UDP formatted response we append the port to our found UDP ports.
    Otherwise we append it to our closed ports.

    Args:
        ip (string): The target ip as a string.
        to_scan (list): A list containing the UDP ports to be scanned.

    Returns:
        list, list: A list of open ports and a list of closed ports
    """

    foundOpen = []
    foundClosed = []

    print(
        style(
            f"---[Scanning for open UDP ports on host {ip}]---",
            1,
            33,
            40))
    for port in to_scan:
        answer = sr1(IP(dst=str(ip)) /
                     UDP(dport=int(port)), timeout=5, verbose=0)
        if answer is not None:
            if answer.haslayer(UDP):
                print(style(f"UDP port {port} is open!", 0, 33, 40))
                foundOpen.append(str(port))
            else:
                foundClosed.append(str(port))
    if len(foundOpen) == 0:
        print(style("No open UDP ports found.", 0, 33, 40))
    return foundOpen, foundClosed


def discover_hostname(ip):
    """This function retrieves the hostname from a remote host using
    the 'socket' module with the function 'gethosstbyaddr()'.

    Args:
        ip (string): The IP to retrieve the hostname from.

    Returns:
        string : The found hostname
    """

    print(style(f"---[Hostname]---", 1, 33, 40))
    hostname = "Not found"
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        print(style(f"Hostname: {hostname}", 0, 33, 40))
    except BaseException:
        print(
            style(
                f"Unable to find hostname. Try clearing your DNS cache.",
                0,
                33,
                40))

    return hostname


def discover_OS(ip):
    """This function uses the NMAP python package to try to discover the OS on a remote host and then prints it to the console alongside a likelihood percentage.
    If multiple OS'es are suspected then those will also be printed out.

    Args:
        ip (string): The target IP address as a string.
    """
    scanner = nmap.PortScanner()
    ports = '1-1024'
    scanner.scan(ip, arguments='-p {0} -O -T4 '.format(ports))
    # print(scanner._nmap_last_output)
    print(style(f"---[Possible OS matches]---", 1, 33, 40))
    try:
        result = scanner[ip]
        if 'osmatch' in result:
            for match in result['osmatch']:
                print(
                    style(
                        f"OS: {match['name']} | Accuracy: {match['accuracy']}%",
                        0,
                        33,
                        40))
        else:
            print(style(f"Unable to determine OS for {ip}", 0, 33, 40))
    except BaseException:
        print(style(f"Unable to determine OS for {ip}", 0, 33, 40))


def discover_services(ip, ports):
    """This function uses the NMAP python package to try to discover the services on a target behind earlier found ports.
    Results are neatly printed to the console using the PrettyTables library.

    Args:
        ip (string): The target IP address
        ports (list): The earlier found ports (both TCP and UDP)

    """
    ports = ",".join(ports)
    scanner = nmap.PortScanner()
    print(style("---[Trying to identify open services...]---", 1, 33, 40))
    scanner.scan(ip, arguments='-sV -sU -p {0} -T4 '.format(ports))
    try:
        result = scanner[ip]
    except BaseException:
        print(
            style(
                f"ERROR: service scan on {ip} failed (maybe no TCP/UDP port were found previously?). Skipping.",
                0,
                31,
                40))
        return

    def ifEmptyReplace(string):
        if string == "":
            return "Unknown"
        else:
            return string

    service_table = PrettyTable()
    service_table.field_names = ["Port", "Service", "Name", "Version"]

    for protocol in result.all_protocols():
        port_ind = result[protocol].keys()
        for port in port_ind:
            service_table.add_row([port,
                                   ifEmptyReplace(result[protocol][port]['name']),
                                   ifEmptyReplace(result[protocol][port]['product']),
                                   ifEmptyReplace(result[protocol][port]['version'])])

    print(service_table)


class PortRangeAction(argparse.Action):
    '''
    This class is used by the 'action' attribute for the parset.add_argument() function.
    It receives the values from the port flags and checks if they are valid and whether or not
    they are a range.

    Values can be seperated by spaces.

    The __call__ function is the code that will be run as our 'action'.
    '''

    def __call__(self, parser, namespace, values, option_string=None):
        try:
            if values == []:
                ports = self.const
            else:
                ports = []
                for port_range in values:
                    port_range_pattern = r'^(\d+)-(\d+)$'
                    match = re.match(port_range_pattern, port_range)

                    if match:
                        start_port = int(match.group(1))
                        end_port = int(match.group(2))
                        if start_port > end_port:
                            raise argparse.ArgumentTypeError(
                                "Invalid port range: start port must be less than or equal to end port")
                        ports.extend(list(range(start_port, end_port + 1)))
                    else:
                        try:
                            port = int(port_range)
                            if port < 1 or port > 65535:
                                raise argparse.ArgumentTypeError(
                                    "Invalid port: port must be between 1 and 65535")
                            ports.append(port)
                        except ValueError:
                            raise argparse.ArgumentTypeError(
                                "Invalid port or port range")

            setattr(namespace, self.dest, ports)
        except BaseException:
            print(
                style(
                    "ERROR: an invalid port was parsed to -TP or -UP. Please use valid port (ranges) between 1 and 65535.",
                    1,
                    31,
                    40))
            exit(1)


def ip_range(start_ip, end_ip):
    """This function creates a list of IP addresses based on a lower (start_ip) and upper IP (end_ip).
    It is mainly used in the IP list action class.

    Args:
        start_ip (string): The lower ip of the IP range
        end_ip (string): The upper ip of the IP range

    Returns:
        list: A list of IP adressess
    """
    start = ipaddress.ip_address(start_ip)
    end = ipaddress.ip_address(end_ip)
    return [ipaddress.ip_address(ip) for ip in range(int(start), int(end) + 1)]


class IPListAction(argparse.Action):
    '''
    This class is used by the 'action' attribute for the parset.add_argument() function.
    It receives the values from the targets flag and checks if they are valid and whether or not
    they are a range.

    Values can be seperated by spaces. The CIDR notation is also valid, which is particularly handy.

    The __call__ function is the code that will be run as our 'action'.
    '''

    def __call__(self, parser, namespace, values, option_string=None):
        all_ips = []
        try:
            for ip_arg in values:
                if '-' in ip_arg:
                    start_ip, end_ip = ip_arg.split('-')
                    all_ips.extend(str(ip)
                                   for ip in ip_range(start_ip, end_ip))
                elif '/' in ip_arg:
                    all_ips.extend(str(ip)
                                   for ip in ipaddress.ip_network(ip_arg).hosts())
                else:
                    all_ips.append(str(ipaddress.ip_address(ip_arg)))
        except BaseException:
            print(style("ERROR: an invalid targets '-T' argument was provided. Only the following are allowed: '10.0.0.1' single addresses, '10.0.0.1-10.0.0.10' address ranges and '10.0.0.0/24' CIDR notation. If you provide multiple targets please separate with spaces.", 1, 31, 40))
            exit(1)

        setattr(namespace, self.dest, all_ips)


def current_time():
    """This function returns the current date and time. It serves as a syntax shortcut.

    Returns:
        string: The current date and time.
    """
    now = datetime.now()
    current_time = now.strftime("%d/%m/%Y %H:%M:%S")
    return current_time


'''
Now that all the functions are in place, we start by collecting flags/arguments.
We create a new ArgumentParser object and repeatedly use the add_argument() function on it to configure our arguments.

In this function we define the flag to be used, wheter or not it is required and/or multiple values are expected and the help text.

We also make use of the action attribute in order to call our 'IPListAction' or 'PortRangeAction' class to parse the IP/port values
correctly.

Once the parser has been correctly configured, we use the parse_args() function on it to create the corresponding attributes and values on our
parser object.
'''

parser = argparse.ArgumentParser(
    description="This script serves as network scanner. All flags are optional. If no flags are parsed a regular complete scan will be performed.")

parser.add_argument(
    '-T',
    '--targets',
    nargs='+',
    action=IPListAction,
    default=argparse.SUPPRESS,
    help='Target IP address(es). Valid arguments: <IP> | <lowerIP>-<upperIP> | <CIDR notation>. Make sure to seperate with spaces.')
parser.add_argument(
    '-TP',
    '--tcp',
    nargs='*',
    const=mostCommonTCP,
    action=PortRangeAction,
    help="TCP ports to scan. Valid arguments: <port> | <lowerport-upperport>. Use spaces to separate values. If this flag receives no arguments, the 100 most common ports will be used. No TCP scans will be performed without this flag.")
parser.add_argument(
    '-UP',
    '--udp',
    nargs='*',
    const=mostCommonUDP,
    action=PortRangeAction,
    help="UDP ports to scan. Valid arguments: <port> | <lowerport-upperport>. Use spaces to separate values. If this flag receives no arguments, the 25 most common ports will be used. No UDP scans will be performed without this flag.")
parser.add_argument(
    '-S',
    '--services',
    type=str,
    nargs="*",
    default=argparse.SUPPRESS,
    help="Scan for services behind the found ports. This flag accepts no arguments.")
parser.add_argument(
    '-M',
    '--MAC',
    type=str,
    nargs="*",
    default=argparse.SUPPRESS,
    help="Return the hosts MAC address. Only works on local networks. This flag accepts no arguments.")
parser.add_argument(
    '-O',
    '--os',
    type=str,
    nargs="*",
    default=argparse.SUPPRESS,
    help="Try to guess the host's OS. This flag accepts no arguments.")
parser.add_argument(
    '-H',
    '--hostname',
    type=str,
    nargs="*",
    default=argparse.SUPPRESS,
    help="Resolve the hostname. This flag accepts no arguments.")

args = parser.parse_args()

'''
We first set some default values for our script. The first three values will be our target lists, of which the target IP's can be filled
out directly as we know target IP's HAVE to be parsed.

The other variables represent booleans corresponding to whether or not we should scan for those parameters.
'''

if (not hasattr(args, 'targets')):
    print(style("ERROR: The -T targets flag is required!", 1, 31, 40))
    print(style("The argument can be provided in the following ways: '10.0.0.1' single addresses, '10.0.0.1-10.0.0.10' address ranges and '10.0.0.0/24' CIDR notation. If you provide multiple targets please separate them with spaces.", 1, 31, 40))
    exit(1)

iptargets = list(dict.fromkeys(args.targets))
tcptargets = []
udptargets = []
gettcp = False
getudp = False
getservices = False
getos = False
gethostname = False
getmac = False

'''
This scan_for variable will be used as a string to be printed to the console, detailing which parameters we are
scanning for.
'''
scan_for = ""


'''
This if/else statement check wheter or not no other flags appart from the -T target flag has been set.
If this is the case, we apply a default template to our scan - meaning we scan for everything.

Else if other flags have been used, we check each one and set the corresponding values.

The TP and UP flags are unique in that one of three scenarios apply to them:
    1. The flag has not been used, meaning we will not be performing a TCP/UDP scan.
    2. The flag has been used, but no parameter was given. A default port range will be assigned and the scan will still be performed.
    3. The flag has been used and a parameter was given. The parameters will be applied and the scan will be performed.
'''

if (args.tcp is None and args.udp is None and not hasattr(args,
    'services') and not hasattr(args,
    'os') and not hasattr(args,
    'hostname') and not hasattr(args,
                                'MAC')):
    print("Only targets have been provided as an argument, setting scan preset to default.")
    gettcp = True
    tcptargets = mostCommonTCP
    getudp = True
    udptargets = mostCommonUDP
    getservices = True
    getos = True
    gethostname = True
    getmac = True
    scan_for = "| Hostname | MAC address | OS | TCP ports | UDP Ports | Services"
else:
    if (args.tcp is not None):
        gettcp = True
        tcptargets = list(dict.fromkeys(args.tcp))
        scan_for += "| TCP ports "
    if (args.udp is not None):
        getudp = True
        udptargets = list(dict.fromkeys(args.udp))
        scan_for += "| UDP ports "
    if (hasattr(args, 'services')):
        getservices = True
        scan_for += "| SERVICES "
    if (hasattr(args, 'os')):
        getos = True
        scan_for += "| OS "
    if (hasattr(args, 'hostname')):
        gethostname = True
        scan_for += "| Hostname "
    if (hasattr(args, 'MAC')):
        getmac = True
        scan_for += "| MAC address "


'''
Here we print the current configuration, and allow the user a brief window to cancel the script should
they be unhappy with the configuration.
'''

print(style(f"==========[Scan configuration: ]==========", 7, 34, 40))
print(style(f"---[Scanning for: ]---", 1, 34, 40))
print(style(f"{scan_for[2:]}", 0, 34, 40))

if (gettcp):
    print(style(f"---[TCP ports to scan: ]---", 1, 34, 40))
    print(style(f"{tcptargets}", 0, 34, 40))
if (getudp):
    print(style(f"---[UDP ports to scan: ]---", 1, 34, 40))
    print(style(f"{udptargets}", 0, 34, 40))
print(
    style(
        f"Scan starting in 15 seconds. Please cancel (CTRL + C) now if you are unhappy with the parameters.",
        7,
        34,
        40))
time.sleep(15)
print(style(f"Starting VisLens scan at {current_time()}", 7, 34, 40))
tstart = time.time()

'''
Here the script starts and we begin with our initial host discovery, as per the function we created.
All live hosts are put into a list called livehosts. A timestamp is also created for the start of our scan to later
be compared to the end timestamp for a time measurement.
'''

livehosts = discover_hosts(iptargets)


'''
Here, we begin iterating through all of the live hosts. For each boolean that is True, a corresponding scan will be performed.
We also keep track of how many hosts have been scanned out of all the hosts, to give insight into the progress of the script.
'''

count = 1
tot = len(livehosts)
for host in livehosts:
    print(
        style(
            f"==========[Starting scans for: {host} | Host {count} out of {tot}]==========",
            7,
            33,
            40))
    if gethostname:
        discover_hostname(host)
    if getmac:
        discover_MAC(host)
    if getos:
        discover_OS(host)
    service_ports = []
    if gettcp:
        openports, _ = discover_tcp_ports(host, tcptargets)
        service_ports += openports
    if getudp:
        openports, _ = discover_udp_ports(host, udptargets)
        service_ports += openports
    if getservices:
        discover_services(host, service_ports)
    count += 1

'''
Once our script is finished, we provide the user with a timing of how long the script has taken.
'''
tfinish = time.time()
print(style(f"Scan completed in {round(tfinish-tstart,2)} seconds", 7, 32, 40))
