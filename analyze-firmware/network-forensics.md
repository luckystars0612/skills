# Network Forensics

Techniques for analyzing network traffic from robot systems. Covers PCAP analysis, protocol reverse engineering, robot-specific traffic analysis, credential extraction, traffic generation, firmware update interception, and side-channel analysis.

---

## PCAP Analysis

### Basic PCAP Inspection

```bash
# File info
capinfos <pcap_file> 2>/dev/null

# Quick statistics
tshark -r <pcap_file> -q -z io,stat,1 2>/dev/null | head -20

# Protocol hierarchy
tshark -r <pcap_file> -q -z io,phs 2>/dev/null

# Conversation list (top talkers)
tshark -r <pcap_file> -q -z conv,ip 2>/dev/null | head -20

# Endpoint list
tshark -r <pcap_file> -q -z endpoints,ip 2>/dev/null | head -20
```

### Protocol-Specific Filters

```bash
# HTTP traffic
tshark -r <pcap_file> -Y 'http' -T fields -e ip.src -e ip.dst -e http.request.method -e http.request.uri 2>/dev/null | head -20

# DNS queries
tshark -r <pcap_file> -Y 'dns.qr==0' -T fields -e ip.src -e dns.qry.name 2>/dev/null | head -20

# TCP streams
tshark -r <pcap_file> -q -z follow,tcp,ascii,0 2>/dev/null | head -50

# UDP traffic
tshark -r <pcap_file> -Y 'udp' -T fields -e ip.src -e ip.dst -e udp.srcport -e udp.dstport 2>/dev/null | head -20

# Telnet traffic (plaintext!)
tshark -r <pcap_file> -Y 'telnet' -T fields -e telnet.data 2>/dev/null | head -20

# FTP credentials
tshark -r <pcap_file> -Y 'ftp.request.command == "USER" || ftp.request.command == "PASS"' 2>/dev/null

# SSH handshake info
tshark -r <pcap_file> -Y 'ssh' -T fields -e ip.src -e ip.dst -e ssh.protocol 2>/dev/null | head -10
```

### Conversation Extraction

```bash
# Extract all TCP streams to files
mkdir -p /tmp/streams
tshark -r <pcap_file> -q -z follow,tcp,raw,0 2>/dev/null > /tmp/streams/stream_0.hex

# Extract HTTP objects (files transferred)
mkdir -p /tmp/http_objects
tshark -r <pcap_file> --export-objects http,/tmp/http_objects 2>/dev/null
ls -la /tmp/http_objects/

# Extract files from SMB
tshark -r <pcap_file> --export-objects smb,/tmp/smb_objects 2>/dev/null

# Extract TFTP files
tshark -r <pcap_file> --export-objects tftp,/tmp/tftp_objects 2>/dev/null
```

### Wireshark Display Filters (Quick Reference)

```
# By protocol
tcp                          # All TCP
udp                          # All UDP
http                         # HTTP traffic
tls                          # TLS/SSL traffic
mqtt                         # MQTT protocol
modbus                       # Modbus TCP
opcua                        # OPC UA

# By address
ip.addr == 192.168.1.1      # Traffic to/from IP
ip.src == 192.168.1.1       # Traffic from IP
ip.dst == 192.168.1.0/24    # Traffic to subnet
tcp.port == 502              # Modbus port
udp.port == 7400             # DDS discovery port

# By content
tcp contains "password"       # TCP data containing string
http.request.uri contains "admin"  # HTTP requests to admin
frame contains "error"        # Any frame containing string

# By flags
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN scan
tcp.flags.rst == 1           # RST packets (port scan, errors)
icmp.type == 8               # Ping requests
```

---

## Protocol Reverse Engineering

### Unknown Protocol Identification

```bash
# Identify unknown protocols by port/behavior
tshark -r <pcap_file> -Y 'not tcp.port in {80,443,22,21,23,53,25,110,143}' \
    -T fields -e tcp.dstport -e udp.dstport 2>/dev/null | sort | uniq -c | sort -rn | head -20

# Analyze unknown protocol structure
tshark -r <pcap_file> -Y 'tcp.port == <unknown_port>' -x 2>/dev/null | head -100

# Extract payload bytes
tshark -r <pcap_file> -Y 'tcp.port == <unknown_port>' \
    -T fields -e data 2>/dev/null | head -20
```

### Binary Protocol Structure Analysis

```python
#!/usr/bin/env python3
"""Analyze binary protocol structure from PCAP."""
from scapy.all import rdpcap, TCP, UDP

packets = rdpcap('<pcap_file>')

# Filter for target port
target_port = 30001  # Example: UR robot port
payloads = []

for pkt in packets:
    if TCP in pkt and (pkt[TCP].sport == target_port or pkt[TCP].dport == target_port):
        payload = bytes(pkt[TCP].payload)
        if len(payload) > 0:
            payloads.append(payload)

# Analyze structure
for i, payload in enumerate(payloads[:10]):
    print(f"\nPacket {i}: {len(payload)} bytes")
    print(f"  Hex: {payload[:32].hex()}")

    # Look for length fields
    if len(payload) >= 4:
        import struct
        len_be = struct.unpack('>I', payload[:4])[0]
        len_le = struct.unpack('<I', payload[:4])[0]
        len_be16 = struct.unpack('>H', payload[:2])[0]
        print(f"  First 4 bytes as BE u32: {len_be}")
        print(f"  First 4 bytes as LE u32: {len_le}")
        print(f"  First 2 bytes as BE u16: {len_be16}")
        if len_be == len(payload) - 4:
            print(f"  → Length-prefixed (BE, excludes prefix)")
        if len_le == len(payload) - 4:
            print(f"  → Length-prefixed (LE, excludes prefix)")
```

### State Machine Reconstruction

```python
#!/usr/bin/env python3
"""Reconstruct protocol state machine from traffic."""
from scapy.all import rdpcap, TCP

packets = rdpcap('<pcap_file>')
target_port = 30001

# Track request-response pairs
states = []
for pkt in packets:
    if TCP in pkt:
        payload = bytes(pkt[TCP].payload)
        if len(payload) > 0:
            direction = 'C→S' if pkt[TCP].dport == target_port else 'S→C'
            states.append({
                'direction': direction,
                'size': len(payload),
                'first_bytes': payload[:8].hex(),
                'ascii': payload[:20].decode('ascii', errors='replace')
            })

# Print state transitions
for i, state in enumerate(states[:30]):
    print(f"  [{i:3d}] {state['direction']} {state['size']:5d}B  {state['first_bytes']}  {state['ascii']}")
```

---

## Robot Traffic Analysis

### DDS/RTPS Traffic

```bash
# DDS uses RTPS (Real-Time Publish-Subscribe) protocol
# Discovery: UDP multicast on 239.255.0.1, port 7400+

# DDS discovery traffic
tshark -r <pcap_file> -Y 'rtps' 2>/dev/null | head -20

# If tshark doesn't recognize RTPS, filter by port
tshark -r <pcap_file> -Y 'udp.port >= 7400 && udp.port <= 7500' 2>/dev/null | head -20

# DDS participant discovery
tshark -r <pcap_file> -Y 'rtps.sm.id == 0x15' -T fields \
    -e ip.src -e rtps.param.participantName 2>/dev/null | head -10

# DDS topic data
tshark -r <pcap_file> -Y 'rtps.sm.id == 0x06' -x 2>/dev/null | head -50

# Extract DDS domain ID
tshark -r <pcap_file> -Y 'rtps' -T fields -e rtps.domain_id 2>/dev/null | sort -u
```

### ROS2 Topic Traffic

```bash
# ROS2 uses DDS underneath — filter RTPS traffic
# Common ROS2 topics in traffic:
# /cmd_vel          — velocity commands
# /joint_states     — joint positions
# /tf               — transform tree
# /scan             — LiDAR data
# /image_raw        — camera data

# If on the ROS2 network, use ros2 tools:
# ros2 topic list
# ros2 topic echo /cmd_vel
# ros2 node list
# ros2 service list

# From PCAP: look for serialized ROS2 messages
tshark -r <pcap_file> -Y 'udp.port >= 7400' -x 2>/dev/null | head -100
```

### MQTT Traffic Analysis

```bash
# MQTT traffic (port 1883 unencrypted, 8883 TLS)
tshark -r <pcap_file> -Y 'mqtt' 2>/dev/null | head -20

# MQTT CONNECT messages (contains credentials)
tshark -r <pcap_file> -Y 'mqtt.msgtype == 1' -T fields \
    -e mqtt.clientid -e mqtt.username -e mqtt.passwd 2>/dev/null

# MQTT PUBLISH messages (data)
tshark -r <pcap_file> -Y 'mqtt.msgtype == 3' -T fields \
    -e mqtt.topic -e mqtt.msg 2>/dev/null | head -20

# MQTT SUBSCRIBE messages (topics of interest)
tshark -r <pcap_file> -Y 'mqtt.msgtype == 8' -T fields \
    -e mqtt.topic 2>/dev/null | head -20

# All MQTT topics
tshark -r <pcap_file> -Y 'mqtt' -T fields -e mqtt.topic 2>/dev/null | sort -u | head -30
```

### CAN Bus Frame Analysis

```bash
# CAN bus traffic (if captured via SocketCAN or candump)
# CAN frames: arbitration ID + data (up to 8 bytes)

# If PCAP contains CAN frames (e.g., via socketcan interface)
tshark -r <pcap_file> -Y 'can' 2>/dev/null | head -20

# Parse candump format
# Format: (timestamp) interface arbitration_id#data
# Example: (1234567890.123456) can0 123#DEADBEEF

# Analyze CAN arbitration IDs
# Lower ID = higher priority
# Standard IDs: 0x000-0x7FF (11-bit)
# Extended IDs: 0x00000000-0x1FFFFFFF (29-bit)

python3 -c "
# Parse CAN log file
import re
from collections import Counter

id_counter = Counter()
with open('<can_log_file>') as f:
    for line in f:
        match = re.search(r'([0-9A-Fa-f]+)#([0-9A-Fa-f]*)', line)
        if match:
            arb_id = match.group(1)
            data = match.group(2)
            id_counter[arb_id] += 1

print('CAN arbitration ID frequency:')
for arb_id, count in id_counter.most_common(20):
    print(f'  0x{arb_id}: {count} frames')
" 2>/dev/null
```

### Modbus TCP Traffic

```bash
# Modbus TCP (port 502)
tshark -r <pcap_file> -Y 'modbus' 2>/dev/null | head -20

# Modbus function codes
tshark -r <pcap_file> -Y 'modbus' -T fields \
    -e ip.src -e ip.dst -e modbus.func_code -e modbus.reference_num -e modbus.data 2>/dev/null | head -20

# Common Modbus function codes:
# 0x01: Read Coils
# 0x02: Read Discrete Inputs
# 0x03: Read Holding Registers
# 0x04: Read Input Registers
# 0x05: Write Single Coil
# 0x06: Write Single Register
# 0x0F: Write Multiple Coils
# 0x10: Write Multiple Registers

# Write operations are security-critical — they modify physical process
tshark -r <pcap_file> -Y 'modbus.func_code == 5 || modbus.func_code == 6 || modbus.func_code == 15 || modbus.func_code == 16' 2>/dev/null | head -10
```

### EtherCAT Frame Analysis

```bash
# EtherCAT traffic (EtherType 0x88A4)
tshark -r <pcap_file> -Y 'ecat' 2>/dev/null | head -20

# EtherCAT mailbox protocol
tshark -r <pcap_file> -Y 'ecat_mailbox' 2>/dev/null | head -20

# CoE (CANopen over EtherCAT)
tshark -r <pcap_file> -Y 'ecat_mailbox.coe' 2>/dev/null | head -20
```

---

## Credential Extraction

### Plaintext Credentials in Traffic

```bash
# HTTP Basic Auth
tshark -r <pcap_file> -Y 'http.authorization' -T fields \
    -e ip.src -e http.authorization 2>/dev/null | head -10
# Decode: echo "<base64>" | base64 -d

# HTTP POST forms with credentials
tshark -r <pcap_file> -Y 'http.request.method == "POST"' -T fields \
    -e ip.src -e http.request.uri -e http.file_data 2>/dev/null | \
    grep -iE 'password|passwd|login|user' | head -10

# FTP credentials
tshark -r <pcap_file> -Y 'ftp.request.command == "USER" || ftp.request.command == "PASS"' \
    -T fields -e ip.src -e ftp.request.command -e ftp.request.arg 2>/dev/null

# Telnet credentials (captured in telnet.data)
tshark -r <pcap_file> -Y 'telnet' -T fields -e telnet.data 2>/dev/null | head -20

# MQTT credentials
tshark -r <pcap_file> -Y 'mqtt.msgtype == 1' -T fields \
    -e ip.src -e mqtt.username -e mqtt.passwd 2>/dev/null

# SNMP community strings
tshark -r <pcap_file> -Y 'snmp' -T fields -e snmp.community 2>/dev/null | sort -u
```

### Authentication Handshake Capture

```bash
# NTLM hashes
tshark -r <pcap_file> -Y 'ntlmssp' -T fields \
    -e ntlmssp.auth.username -e ntlmssp.auth.domain 2>/dev/null | head -10

# Kerberos tickets
tshark -r <pcap_file> -Y 'kerberos' 2>/dev/null | head -10

# SSH key exchange (algorithm info, not keys)
tshark -r <pcap_file> -Y 'ssh.kex' -T fields \
    -e ssh.kex_algorithms -e ssh.encryption_algorithms_client_to_server 2>/dev/null | head -5
```

### Session Token Extraction

```bash
# HTTP cookies
tshark -r <pcap_file> -Y 'http.cookie' -T fields \
    -e ip.src -e http.cookie 2>/dev/null | head -10

# JWT tokens
tshark -r <pcap_file> -Y 'http.authorization contains "Bearer"' -T fields \
    -e ip.src -e http.authorization 2>/dev/null | head -5

# Decode JWT (header.payload.signature, base64url-encoded)
# echo "<jwt_token>" | cut -d. -f2 | base64 -d 2>/dev/null
```

---

## Traffic Generation and Testing

### Crafting Protocol-Specific Packets

```python
#!/usr/bin/env python3
"""Craft packets for robot protocol testing."""
from scapy.all import *

# Modbus TCP write register
def modbus_write_register(target_ip, register, value):
    """Write a single Modbus holding register."""
    # Modbus TCP header + Write Single Register (FC 0x06)
    modbus = bytes([
        0x00, 0x01,  # Transaction ID
        0x00, 0x00,  # Protocol ID (Modbus)
        0x00, 0x06,  # Length
        0x01,        # Unit ID
        0x06,        # Function code: Write Single Register
        (register >> 8) & 0xFF, register & 0xFF,  # Register address
        (value >> 8) & 0xFF, value & 0xFF           # Value
    ])
    # send(IP(dst=target_ip)/TCP(dport=502)/Raw(modbus))
    return modbus

# MQTT publish (for testing without a client)
def mqtt_publish(topic, message):
    """Craft MQTT PUBLISH packet."""
    topic_bytes = topic.encode()
    msg_bytes = message.encode()
    # Fixed header: PUBLISH (0x30) + remaining length
    remaining = 2 + len(topic_bytes) + len(msg_bytes)
    packet = bytes([0x30, remaining])
    packet += len(topic_bytes).to_bytes(2, 'big') + topic_bytes
    packet += msg_bytes
    return packet
```

### Replay Attacks

```python
#!/usr/bin/env python3
"""Replay captured robot control packets."""
from scapy.all import rdpcap, sendp, TCP, IP

# Read original capture
packets = rdpcap('<pcap_file>')

# Filter for robot control packets
control_packets = [pkt for pkt in packets
                   if TCP in pkt and pkt[TCP].dport == 30001]  # UR robot port

# Replay to target
# for pkt in control_packets:
#     pkt[IP].dst = '<target_ip>'
#     del pkt[IP].chksum
#     del pkt[TCP].chksum
#     sendp(pkt, iface='eth0')
#     time.sleep(0.01)

print(f"Found {len(control_packets)} control packets to replay")
```

---

## Firmware Update Traffic

### Capturing OTA Update Process

```bash
# Capture traffic during firmware update
# tcpdump -i <interface> -w /tmp/ota_capture.pcap host <device_ip>

# Analyze update traffic
tshark -r /tmp/ota_capture.pcap -q -z io,phs 2>/dev/null

# Look for firmware download
tshark -r /tmp/ota_capture.pcap -Y 'http.response.code == 200' -T fields \
    -e http.content_type -e http.content_length -e http.request.uri 2>/dev/null | head -10

# Extract downloaded firmware
tshark -r /tmp/ota_capture.pcap --export-objects http,/tmp/ota_objects 2>/dev/null
ls -la /tmp/ota_objects/

# Check for TFTP firmware transfer
tshark -r /tmp/ota_capture.pcap -Y 'tftp' 2>/dev/null | head -10
tshark -r /tmp/ota_capture.pcap --export-objects tftp,/tmp/tftp_objects 2>/dev/null
```

### Man-in-the-Middle Analysis

```bash
# Check if firmware update uses TLS
tshark -r /tmp/ota_capture.pcap -Y 'tls' -T fields \
    -e tls.handshake.type -e tls.handshake.extensions_server_name 2>/dev/null | head -10

# If no TLS → MitM is trivial, firmware can be replaced
# If TLS with no cert pinning → MitM with custom CA
# If TLS with cert pinning → need to bypass pinning

# Check update integrity verification
# Look for hash/signature verification in update protocol
tshark -r /tmp/ota_capture.pcap -Y 'http' -T fields -e http.request.uri 2>/dev/null | \
    grep -iE '(hash|signature|checksum|verify|manifest)' | head -5
```

---

## Side-Channel via Network

### Timing Analysis

```python
#!/usr/bin/env python3
"""Timing-based side channel via network responses."""
from scapy.all import rdpcap, TCP
import statistics

packets = rdpcap('<pcap_file>')

# Calculate response times for authentication attempts
request_times = {}
response_times = []

for pkt in packets:
    if TCP in pkt:
        # Track SYN-ACK timing, or application-layer request-response
        pass

# Timing differences may reveal:
# - Correct vs incorrect username (different code path)
# - Partial password match (early exit on mismatch)
# - Valid vs invalid token
```

### Response Size Analysis

```bash
# Different response sizes for valid vs invalid inputs
tshark -r <pcap_file> -Y 'tcp.port == <service_port>' -T fields \
    -e frame.time_relative -e ip.src -e tcp.len 2>/dev/null | head -50

# Group by response size to identify different outcomes
tshark -r <pcap_file> -Y 'tcp.port == <service_port> && tcp.len > 0' -T fields \
    -e tcp.len 2>/dev/null | sort | uniq -c | sort -rn | head -10
```

### Error Message Enumeration

```bash
# Different error messages for different failure modes
tshark -r <pcap_file> -Y 'tcp.port == <service_port>' -T fields -e data 2>/dev/null | \
    while read hex; do
        echo "$hex" | xxd -r -p 2>/dev/null
        echo "---"
    done | grep -iE '(error|invalid|denied|forbidden|unauthorized|not found|fail)' | \
    sort -u | head -10
```

---

## Traffic Capture Checklist for Robot Systems

When capturing traffic from a robot system, prioritize:

| Priority | Traffic Type | Port/Protocol | Why |
|----------|-------------|---------------|-----|
| 1 | Robot control commands | Vendor-specific (e.g., 30001-30004) | Direct control of robot motion |
| 2 | Safety controller | Varies | Safety-critical communication |
| 3 | DDS/ROS2 | UDP 7400+ | Robot topic pub/sub |
| 4 | MQTT | 1883/8883 | Sensor data and commands |
| 5 | Modbus | 502 | Industrial process control |
| 6 | CAN bus | N/A (layer 2) | Motor/sensor control |
| 7 | HTTP/HTTPS | 80/443 | Web interface, API |
| 8 | SSH | 22 | Remote management |
| 9 | Firmware update | Varies | Update mechanism |
| 10 | DNS | 53 | Service discovery, cloud comms |
