from scapy.all import *
from threading import Thread
import pandas
import time
import os

# initialize the networks dataframe that will contain all access points nearby
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto", "AP"])
# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

stations = pandas.DataFrame(columns=["AP", "Station"])
stations.set_index("Station", inplace=True)

all_packets = pandas.DataFrame(columns=["addr1", "addr2", "addr3", "addr4"])

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        ap = packet[Dot11].addr3

        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto, ap)



    
    if packet.haslayer(Dot11FCS):
        # Get stations and associated APs
        addr1 = packet[Dot11FCS].addr1
        addr2 = packet[Dot11FCS].addr2
        stations.loc[addr1] = (addr2)
    

def print_all():
    while True:
        os.system("clear")
        print(networks)
        print("\n\n")
        print(stations)
        time.sleep(1)


def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch % 14 + 1
        time.sleep(0.5)


if __name__ == "__main__":
    # interface name, check using iwconfig
    interface = "wlan0"
    # start the thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    # start sniffing
    sniff(prn=callback, iface=interface)