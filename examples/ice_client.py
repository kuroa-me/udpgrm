#!/usr/bin/env python3
from scapy.all import *
from scapy.contrib.stun import STUN, STUNUsername, STUNUseCandidate, STUNIceControlling
import socket

load_contrib("stun")

def send_stun_with_username(server_ip, server_port, username):
    """
    Send a STUN Binding Request with USERNAME attribute using Scapy.
    
    Args:
        server_ip: Target STUN server IP address
        server_port: Target STUN server port (typically 3478)
        username: ICE username/ufrag to include in the request
    """
    # Create STUN Binding Request (message type 0x0001)
    stun_pkt = STUN(
        stun_message_type="Binding request",
        transaction_id=int('6f98e9b76e6b8dffaf1d39a6', 16))

    # Add some well-known attributes if needed
    stun_pkt /= STUNUseCandidate()
    stun_pkt /= STUNIceControlling(tie_breaker=0x123456789ABCDEF0)
    
    # Add USERNAME attribute (type 0x0006)
    stun_pkt /= STUNUsername(username=username)
    
    # Send packet
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(bytes(stun_pkt), (server_ip, server_port))
    
    stun_pkt.show()
    
    # Wait for response
    sock.settimeout(5)
    try:
        data, addr = sock.recvfrom(1024)
        print(f"\nReceived response from {addr}")
        resp = STUN(data)
        resp.show()
    except socket.timeout:
        print("No response received (timeout)")
    finally:
        sock.close()

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <server_ip> <server_port> <username>")
        print(f"Example: {sys.argv[0]} 127.0.0.1 3478 myufrag123")
        sys.exit(1)
    
    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    username = sys.argv[3]
    
    send_stun_with_username(server_ip, server_port, username)