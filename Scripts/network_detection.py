from scapy.all import *

def detect_malformed_smb(pcap_file):
    """
    Analyses PCAP for malformed SMB packets
    """
    print(f"[*] Analyzing: {pcap_file}")
    
    packets = rdpcap(pcap_file)
    detections = []
    
    for i, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt[TCP].dport == 445:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                
                # Check for SMB2 signature
                if payload.startswith(b"\xfe\x53\x4d\x42"):
                    # Check for compression signature
                    if b"\xfc\x53\x4d\x42" in payload:
                        # Check for malformed offset (0xFFFFFFFF)
                        if b"\xFF\xFF\xFF\xFF" in payload:
                            detections.append({
                                'packet_num': i,
                                'src': pkt[IP].src if pkt.haslayer(IP) else "Unknown",
                                'dst': pkt[IP].dst if pkt.haslayer(IP) else "Unknown",
                                'reason': "Malformed SMB compression header detected"
                            })
    
    print(f"\n[✓] Analysis complete")
    print(f"[!] Detections: {len(detections)}")
    
    for det in detections:
        print(f"\n  Packet #{det['packet_num']}")
        print(f"    {det['src']} → {det['dst']}")
        print(f"    Reason: {det['reason']}")
    
    return detections

# Test on your captured PCAP
# (You'll need to save the Wireshark capture first)
detect_malformed_smb("C:/ZeroClick_Project/Data/PCAP/vulnerable_test.pcapng")
print("[!] Save your Wireshark capture as PCAP first")
print("[!] Then uncomment the line above and run")