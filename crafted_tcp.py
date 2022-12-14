import sys

from scapy.all import *
from scapy.utils import rdpcap


# VARIABLES
src = sys.argv[1]
dst = sys.argv[1]

pkts=rdpcap("out_of_order_clean.pcap")
for pkt in pkts:
    #pkt[IP].src = src
    #pkt[IP].dst = dst
    sendp(pkt)