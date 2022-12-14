from scapy.all import *

load_layer('tls')

def process_packet(pkt):
    pass
    
print("Running \"sniff\" from scapy library with TCPSession and layer TLS loaded...")
sniff(filter="ip", 
      prn=process_packet,
      session=TCPSession,
      store=False)
