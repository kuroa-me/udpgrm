#!/bin/env python3

import struct
import socket
import time
from socket import (SOL_SOCKET, AF_INET, SOCK_DGRAM, SO_REUSEPORT, IPPROTO_UDP)

UDP_GRM_SOCKET_GEN = 201
UDP_GRM_DISSECTOR = 202
UDP_GRM_UFRAG = 205

DISSECTOR_BESPOKE = 3
DISSECTOR_FLAG_VERBOSE = 0x8000
DIGEST_ICE = 0x1CED

sd = socket.socket(AF_INET, SOCK_DGRAM, 0)
sd.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
sd.bind(("0.0.0.0", 3478))

v = struct.pack("IIII", DISSECTOR_BESPOKE | DISSECTOR_FLAG_VERBOSE, 124, 0, DIGEST_ICE)
sd.setsockopt(IPPROTO_UDP, UDP_GRM_DISSECTOR, v)
sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, 1)
time.sleep(1)

sd.setsockopt(IPPROTO_UDP, UDP_GRM_UFRAG, b"xrBfiZUGniJAmRnw")

while True:
    data, addr = sd.recvfrom(4096)
    print(f"Received {len(data)} bytes from {addr}")
    sd.sendto(data, addr)