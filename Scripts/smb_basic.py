from scapy.all import *

def create_smb_packet(target_ip):
    """
    Creates a basic TCP packet to SMB port (445)
    """
    print(f"Creating SMB packet for {target_ip}")
    
    # IP layer
    ip = IP(dst=target_ip)
    
    # TCP layer - SMB uses port 445
    # SYN flag to start connection
    tcp = TCP(sport=RandShort(), dport=445, flags="S")
    
    # Combine layers
    packet = ip/tcp
    
    return packet

# Test it (don't send yet)
test_packet = create_smb_packet("192.168.10.10")
print("\nPacket created:")
test_packet.show()

print("\n✓ Packet creation successful!")