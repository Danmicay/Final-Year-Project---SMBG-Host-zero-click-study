from scapy.all import *
import time

def test_smb_connectivity(target_ip):
    """
    Tests if we can reach SMB port on target
    """
    print(f"\n[*] Testing SMB connectivity to {target_ip}...")
    
    # Create SYN packet to port 445
    packet = IP(dst=target_ip)/TCP(sport=RandShort(), dport=445, flags="S")
    
    print(f"[*] Sending SYN packet to {target_ip}:445")
    
    # Send and wait for response
    response = sr1(packet, timeout=3, verbose=0)
    
    if response:
        if response.haslayer(TCP):
            if response[TCP].flags == "SA":  # SYN-ACK
                print(f"[✓] SMB port is OPEN - received SYN-ACK")
                return True
            elif response[TCP].flags == "RA":  # RST-ACK
                print(f"[✗] SMB port is CLOSED - received RST")
                return False
    else:
        print(f"[✗] No response from {target_ip}")
        return False

# Test vulnerable VM
print("="*60)
print("SMB PORT CONNECTIVITY TEST")
print("="*60)

vulnerable_vm = "192.168.32.10"  # Change if your IP is different
patched_vm = "192.168.32.20"     # Change if your IP is different

print("\n--- Testing Vulnerable VM ---")
test_smb_connectivity(vulnerable_vm)

print("\n--- Testing Patched VM ---")
test_smb_connectivity(patched_vm)

print("\n[✓] Test complete!")