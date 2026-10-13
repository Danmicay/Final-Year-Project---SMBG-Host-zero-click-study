from scapy.all import *

pcap_file = "C:/ZeroClick_Project/Data/PCAP/host_outgoing_malformed_smb.pcapng"

print(f"Analyzing: {pcap_file}\n")

try:
    packets = rdpcap(pcap_file)
    print(f"[✓] Total packets in file: {len(packets)}\n")
    
    # Check for any SMB traffic
    smb_count = 0
    port_445_count = 0
    
    for pkt in packets:
        if pkt.haslayer(TCP):
            if pkt[TCP].dport == 445 or pkt[TCP].sport == 445:
                port_445_count += 1
                print(f"Found packet to/from port 445:")
                print(f"  {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")
                
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    print(f"  Payload length: {len(payload)} bytes")
                    print(f"  First 20 bytes: {payload[:20].hex()}")
                    print()
    
    print(f"\n[*] Summary:")
    print(f"    Total packets: {len(packets)}")
    print(f"    Port 445 packets: {port_445_count}")
    
except FileNotFoundError:
    print("[✗] PCAP file not found!")
    print("    You need to create it first by:")
    print("    1. Start Wireshark on VM")
    print("    2. Run generate_malformed_smb.py")
    print("    3. Save Wireshark capture as vulnerable_test.pcapng")
except Exception as e:
    print(f"[✗] Error: {e}")