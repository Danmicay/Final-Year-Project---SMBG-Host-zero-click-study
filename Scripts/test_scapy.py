from scapy.all import *

print("Testing Scapy...")

# Create a simple IP packet
packet = IP(dst="8.8.8.8")

# Show packet structure
print("\nPacket structure:")
packet.show()

# Create TCP packet
tcp_packet = IP(dst="192.168.1.1")/TCP(dport=80)
print("\nTCP packet created")
tcp_packet.show()

print("\n✓ Scapy is working correctly!")