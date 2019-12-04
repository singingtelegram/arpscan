#!/usr/bin/env python3
"""
Usage: sudo python3 scan.py network

Portions of this program is adopted from https://github.com/mpostument/hacking_tools/blob/master/network_scanner/network_scanner.py

MIT License

Copyright (c) 2018 Maksym Postument

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import scapy.all as scapy
import argparse
import requests

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # broadcast addr
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    clients_list = []

    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def get_vendor(mac):
    try:
        url = "https://api.macvendors.com/" + mac
        resp = requests.get(url)
        if resp.status_code == 200:
            return resp.text
        else:
            return "lookup failed (" + str(resp.status_code) + ")"
    except Exception as e:
        return "lookup failed"

def print_result(results_list):
    print("IP\t\t\tMAC Address\t\t\tVendor")
    print("-" * 80)
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"] + "\t\t" + get_vendor(client["mac"][:8]))


parser = argparse.ArgumentParser()
parser.add_argument("network", help="Network to scan, like 192.168.0.0/24")
args = parser.parse_args()

if __name__ == "__main__":
    scan_result = scan(args.network)
    print_result(scan_result)
