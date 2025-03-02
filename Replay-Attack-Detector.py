# -*- coding: utf-8 -*-
"""
Created on Sun Mar 2 2:10:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("Replay Attack Detector")
print(Fore.GREEN+font)

import scapy.all as scapy
import time
from collections import defaultdict

# Dictionary to track packet hashes and their timestamps
packet_hashes = defaultdict(list)

# Function to generate a hash for a packet
def get_packet_hash(packet):
    """ Generate a unique hash for the packet based on its contents. """
    return hash(packet.summary())  # You can use any attribute you want to generate a unique hash

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        
        # Get packet hash (based on packet content)
        packet_hash = get_packet_hash(packet)

        # Record the time the packet was seen
        current_time = time.time()
        
        # Check for repeated packets (replay attack)
        if packet_hash in packet_hashes:
            for timestamp in packet_hashes[packet_hash]:
                if current_time - timestamp < 5:  # If the same packet is seen within 5 seconds
                    print(f"Potential Replay Attack detected: Packet from {src_ip} to {dst_ip} is being replayed!")
                    return

        # Add the packet's hash and timestamp to the dictionary
        packet_hashes[packet_hash].append(current_time)
        
        print(f"Received packet from {src_ip} to {dst_ip} with hash: {packet_hash}")

def detect_replay_attack(ip_address):
    print(f"Monitoring traffic to/from {ip_address} for potential Replay Attack...")

    start_time = time.time()
    while time.time() - start_time < 60:  # Monitor for 1 minute for example
        time.sleep(1)

    print(f"No Replay Attack detected within the last minute of monitoring.")

def start_monitoring():
    # Prompt the user to enter the IP address to monitor
    ip_address = input("Enter the IP address to monitor for Replay Attack:")
    
    # Start sniffing packets
    print(f"Starting packet capture for IP: {ip_address}")
    scapy.sniff(prn=packet_callback, filter=f"ip host {ip_address}", store=0, timeout=60)

    # After capturing, analyze the traffic for Replay Attack
    detect_replay_attack(ip_address)

if __name__ == "__main__":
    start_monitoring()
