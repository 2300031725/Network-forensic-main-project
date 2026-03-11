from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Ether, conf
import pandas as pd
import threading
import time
from datetime import datetime, timedelta
import psutil
import subprocess
import platform
import socket

# Global data storage
packet_data = []
traffic_stats = {
    "total_packets": 0,
    "unique_ips": set(),
    "protocols": {},
    "top_sources": {},
    "top_destinations": {},
    "packet_sizes": {"0-100": 0, "100-500": 0, "500-1000": 0, "1000+": 0},
    "alerts": []
}

lock = threading.RLock()
sniffer_thread = None
is_running = False
use_psutil_fallback = True

# Metrics history for Trend Chart
traffic_trend = []
last_total_packets = 0

# Storage for Imported Data
imported_stats = None

# Tunable detection and analytics settings.
DETECTION_CONFIG = {
    "packet_log_limit": 5000,
    "alerts_limit": 1000,
    "scan_port_threshold": 15,
    "scan_dedup_window": 10,
    "flood_pps_threshold": 260,
    "ddos_pps_threshold": 500,
    "jumbo_packet_threshold": 3000,
    "sensitive_ports": {22, 23, 3389, 21},
    "sensitive_ports_rate_threshold": 20,
    "malware_signature_ports": {4444, 6667, 1337},
    "anomaly_window_size": 200,
    "top_entities_limit": 10,
    # Keep ~24h+ trend history at 2s polling (24h = 43,200 points).
    "trend_max_points": 50000,
    "live_timeline_minutes": 10,
    "timeline_max_points": 20,
    "timeline_severity_multiplier": 10,
    "cpu_ram_critical_threshold": 90,
    "import_large_packet_threshold": 1400,
    "risk_low_threshold": 300,
    "risk_medium_threshold": 600,
    "risk_low_scale_max": 30,
    "risk_medium_scale_max": 70,
    "risk_high_scale_max": 100,
    "protocol_port_map_tcp": {
        80: "HTTP",
        443: "HTTPS",
        22: "SSH",
        21: "FTP",
        25: "SMTP",
    },
    "protocol_port_map_udp": {
        67: "DHCP",
        123: "NTP",
    },
    "packet_size_ranges": (
        (100, "0-100"),
        (500, "100-500"),
        (1000, "500-1000"),
    ),
    "protocol_risk_weight": {
        "ICMP": 0.70,
        "UDP": 0.62,
        "TCP": 0.52,
        "HTTP": 0.58,
        "HTTPS": 0.42,
        "DNS": 0.55,
        "DHCP": 0.40,
        "NTP": 0.48,
        "SSH": 0.60,
        "FTP": 0.68,
        "SMTP": 0.64,
        "ARP": 0.35,
        "Other": 0.45,
        "Unknown": 0.45,
    },
    "score_weights": {
        "frequency": 0.30,
        "size": 0.15,
        "severity": 0.20,
        "threat": 0.10,
        "protocol": 0.10,
        "destination": 0.15,
    },
}

SEVERITY_WEIGHT = {
    "Low": 0.15,
    "Medium": 0.35,
    "High": 0.65,
    "Critical": 0.9,
}

# Common IANA protocol / IPv6 next-header number names.
PROTOCOL_NUMBER_NAME = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    4: "IP_IN_IP",
    6: "TCP",
    8: "EGP",
    17: "UDP",
    41: "IPV6",
    43: "IPV6_ROUTE",
    44: "IPV6_FRAG",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPV6",
    59: "IPV6_NO_NEXT",
    60: "IPV6_OPTS",
    88: "EIGRP",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    132: "SCTP",
}

import io
import json
import scapy.all as scapy
from scapy.utils import rdpcap
import pdfplumber


def _normalize_protocol(alert_type, fallback_protocol):
    alert_type_l = (alert_type or "").lower()
    if "scan" in alert_type_l:
        return "TCP"
    return fallback_protocol if fallback_protocol else "Unknown"


def _compute_anomaly_score(
    freq,
    max_freq,
    packet_length,
    severity,
    is_threat,
    protocol="Unknown",
    destination_freq=0,
    max_destination_freq=1,
    pair_freq=0,
    max_pair_freq=1,
):
    freq_ratio = (freq / max_freq) if max_freq else 0.0
    size_ratio = min(packet_length / max(1, DETECTION_CONFIG["jumbo_packet_threshold"]), 1.0)
    severity_ratio = SEVERITY_WEIGHT.get(severity, 0.1)
    threat_ratio = 1.0 if is_threat else 0.0
    protocol_ratio = DETECTION_CONFIG["protocol_risk_weight"].get(protocol, DETECTION_CONFIG["protocol_risk_weight"]["Unknown"])
    # Rare destination targets and repeated src-dst-proto pairs get higher score.
    destination_novelty = 1.0 - ((destination_freq / max_destination_freq) if max_destination_freq else 0.0)
    pair_ratio = (pair_freq / max_pair_freq) if max_pair_freq else 0.0
    destination_signal = (0.6 * destination_novelty) + (0.4 * pair_ratio)
    weights = DETECTION_CONFIG["score_weights"]
    score = (
        (weights["frequency"] * freq_ratio)
        + (weights["size"] * size_ratio)
        + (weights["severity"] * severity_ratio)
        + (weights["threat"] * threat_ratio)
        + (weights["protocol"] * protocol_ratio)
        + (weights["destination"] * destination_signal)
    )
    return max(0.0, min(1.0, score))


def _get_dominant_protocol(protocols):
    protocol_items = [(name, count) for name, count in protocols.items() if count > 0]
    if not protocol_items:
        return "N/A"
    dominant_name, dominant_count = max(protocol_items, key=lambda x: x[1])
    total = max(1, sum(count for _, count in protocol_items))
    pct = (dominant_count / total) * 100
    return f"{dominant_name} ({pct:.1f}%)"


def _get_packet_size_summary(packet_sizes):
    if not packet_sizes:
        return "N/A"
    largest_bucket, largest_count = max(packet_sizes.items(), key=lambda x: x[1])
    if largest_count <= 0:
        return "N/A"
    return largest_bucket + " bytes"


def _get_peak_time(trend_points):
    if not trend_points:
        return "N/A"
    peak = max(trend_points, key=lambda x: x.get("packets", 0))
    packets = peak.get("packets", 0)
    if packets <= 0:
        return "N/A"
    return f"{peak.get('time', 'N/A')} ({packets} packets)"


def _classify_packet_size(length):
    for threshold, bucket in DETECTION_CONFIG["packet_size_ranges"]:
        if length < threshold:
            return bucket
    return "1000+"


def _protocol_from_ports(base_protocol, sport, dport):
    if base_protocol == "TCP":
        port_map = DETECTION_CONFIG["protocol_port_map_tcp"]
    elif base_protocol == "UDP":
        port_map = DETECTION_CONFIG["protocol_port_map_udp"]
    else:
        return None

    if sport in port_map:
        return port_map[sport]
    if dport in port_map:
        return port_map[dport]
    return None


def _detect_packet_protocol(packet, sport=0, dport=0):
    if packet.haslayer(scapy.DNS):
        return "DNS"
    if packet.haslayer(scapy.DHCP):
        return "DHCP"
    if packet.haslayer(ARP):
        return "ARP"

    if packet.haslayer(TCP):
        mapped = _protocol_from_ports("TCP", sport, dport)
        return mapped if mapped else "TCP"
    if packet.haslayer(UDP):
        mapped = _protocol_from_ports("UDP", sport, dport)
        return mapped if mapped else "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"

    if IP in packet:
        proto_num = int(packet[IP].proto)
        return _protocol_number_to_name(proto_num, family="ip")
    if IPv6 in packet:
        nh_num = int(packet[IPv6].nh)
        return _protocol_number_to_name(nh_num, family="ipv6")

    try:
        return str(packet.lastlayer().name)
    except Exception:
        return "Other"


def _protocol_number_to_name(number, family="ip"):
    if number in PROTOCOL_NUMBER_NAME:
        return PROTOCOL_NUMBER_NAME[number]

    # OS protocol DB lookup for additional names.
    try:
        socket_name = socket.getprotobynumber(number)
        if socket_name:
            return socket_name.upper().replace("-", "_")
    except Exception:
        pass

    # Fallback keeps visibility for unknown/unassigned values.
    if family == "ipv6":
        return f"IPV6_NH_{number}"
    return f"IP_PROTO_{number}"

# Try to find the best active interface for Scapy
try:
    if not conf.iface:
        # Smart detection: Use the interface that routes to Google DNS (8.8.8.8)
        # This almost always picks the active Wi-Fi or Ethernet adapter with internet access
        best_iface = conf.route.route("8.8.8.8")[1]
        conf.iface = best_iface
        print(f"âœ… Scapy selected active interface: {best_iface}")
    else:
        print(f"âœ… Scapy already configured for interface: {conf.iface}")
except Exception as e:
    print(f"âš ï¸ specific interface detection failed, falling back to default: {e}")
    # Fallback to standard scapy behavior (usually picks first available)
    pass

def process_packet(packet):
    """Callback function for each captured packet via Scapy."""
    global packet_data
    with lock:
        try:
            src_ip = "Unknown"
            dst_ip = "Unknown"
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif IPv6 in packet:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
            elif ARP in packet:
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst
            elif Ether in packet:
                src_ip = packet[Ether].src
                dst_ip = packet[Ether].dst

            length = len(packet)
            timestamp = datetime.now()

            # Determine protocol & extract ports dynamically from packet content.
            sport = 0
            dport = 0
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport

            protocol = _detect_packet_protocol(packet, sport=sport, dport=dport)

            # Update stats (Scapy)
            traffic_stats["unique_ips"].add(src_ip)
            traffic_stats["protocols"][protocol] = traffic_stats["protocols"].get(protocol, 0) + 1
                
            # Top IPs
            traffic_stats["top_sources"][src_ip] = traffic_stats["top_sources"].get(src_ip, 0) + 1
            traffic_stats["top_destinations"][dst_ip] = traffic_stats["top_destinations"].get(dst_ip, 0) + 1

            # Packet Size
            size_bucket = _classify_packet_size(length)
            traffic_stats["packet_sizes"][size_bucket] += 1

            # Add to detailed log 
            packet_data.append({
                "Timestamp": timestamp,
                "Source": src_ip,
                "Destination": dst_ip,
                "Protocol": protocol,
                "Length": length,
                "SrcPort": sport,
                "DstPort": dport
            })
            if len(packet_data) > DETECTION_CONFIG["packet_log_limit"]:
                packet_data.pop(0)

            # --- REAL THREAT DETECTION LOGIC ---

            # 1. Port Scan Detection (Accessing many different Dest Ports)
            # We use a static dict in the function to track this (simplified)
            if not hasattr(process_packet, "scan_tracker"):
                 process_packet.scan_tracker = {} # {src_ip: set(dports)}

            if dport > 0:
                if src_ip not in process_packet.scan_tracker:
                    process_packet.scan_tracker[src_ip] = set()
                process_packet.scan_tracker[src_ip].add(dport)

                # If tracked ports exceed threshold, flag as Port Scan
                if len(process_packet.scan_tracker[src_ip]) > DETECTION_CONFIG["scan_port_threshold"]:
                     # Check if we already alerted this recently
                     already_alerted = any(
                         a['Source'] == src_ip and a['Type'] == 'Port Scan'
                         for a in traffic_stats["alerts"][-DETECTION_CONFIG["scan_dedup_window"]:]
                     )
                     if not already_alerted:
                        traffic_stats["alerts"].append({
                            "Timestamp": timestamp.strftime("%H:%M:%S"),
                            "Type": "Port Scan",
                            "Source": src_ip,
                            "Destination": dst_ip,
                            "Protocol": "TCP", # Scans are usually TCP/UDP
                            "Severity": "High"
                        })
                        # Reset tracker to avoid spamming
                        process_packet.scan_tracker[src_ip] = set()

            # 2. High Volume / Flood Detection (RATE BASED - ROBUST)
            # Track packets per second. If > 50 packets/sec, flag it.
            if not hasattr(process_packet, "rate_tracker"):
                 process_packet.rate_tracker = {} # {src_ip: [current_second, count]}

            current_sec = timestamp.second
            if src_ip not in process_packet.rate_tracker:
                 process_packet.rate_tracker[src_ip] = [current_sec, 0]

            # Reset if second changed
            if process_packet.rate_tracker[src_ip][0] != current_sec:
                 process_packet.rate_tracker[src_ip] = [current_sec, 0]

            # Increment count
            process_packet.rate_tracker[src_ip][1] += 1

            # Check threshold for high packet rate.
            if process_packet.rate_tracker[src_ip][1] > DETECTION_CONFIG["flood_pps_threshold"]:
                 # Only alert once per second per IP to avoid spam
                 if process_packet.rate_tracker[src_ip][1] == (DETECTION_CONFIG["flood_pps_threshold"] + 1):
                    traffic_stats["alerts"].append({
                        "Timestamp": timestamp.strftime("%H:%M:%S"),
                        "Type": "High Traffic Volume",
                        "Source": src_ip,
                        "Destination": dst_ip,
                        "Protocol": protocol,
                        "Severity": "Medium"
                    })
                    # DEBUG: Confirm real destination
                    print(f"âš ï¸ Rate Limit Alert: Src={src_ip} -> Dst={dst_ip} ({process_packet.rate_tracker[src_ip][1]} pps)")

            # 3. Jumbo Frames
            if length > DETECTION_CONFIG["jumbo_packet_threshold"]:
                traffic_stats["alerts"].append({
                    "Timestamp": timestamp.strftime("%H:%M:%S"),
                    "Type": "Abnormal Packet Size",
                    "Source": src_ip,
                    "Destination": dst_ip,
                    "Protocol": protocol,
                    "Severity": "Low"
                })

            # 4. Brute Force (Specific Sensitive Port Activity)
            if dport in DETECTION_CONFIG["sensitive_ports"]:
                # Only flag if we see repeated traffic (Simplified: In strict mode, we log access attempts)
                # For now, we will log it as "Potential Access Attempt" rather than Brute Force to be accurate without counters
                 pass # Reducing noise. Real Brute Force requires state tracking (failed logins).
                 # Let's keep it simple: Only alert if RATE on these ports is high?
                 # OR: Just log strictly.

                 if process_packet.rate_tracker[src_ip][1] > DETECTION_CONFIG["sensitive_ports_rate_threshold"]:
                    traffic_stats["alerts"].append({
                        "Timestamp": timestamp.strftime("%H:%M:%S"),
                        "Type": "Brute Force Attempt",
                        "Source": src_ip,
                        "Destination": dst_ip,
                        "Protocol": protocol,
                        "Severity": "Critical"
                    })

            # 5. Malware / C2 (Strict Port Match Only)
            if dport in DETECTION_CONFIG["malware_signature_ports"]: # Metasploit, IRC Botnet, Elite
                 traffic_stats["alerts"].append({
                        "Timestamp": timestamp.strftime("%H:%M:%S"),
                        "Type": "Malware Signature",
                        "Source": src_ip,
                        "Destination": dst_ip,
                        "Protocol": protocol,
                        "Severity": "Critical"
                    })

            # 6. DDoS (Ultra High Rate)
            if process_packet.rate_tracker[src_ip][1] > DETECTION_CONFIG["ddos_pps_threshold"]:
                 if process_packet.rate_tracker[src_ip][1] == (DETECTION_CONFIG["ddos_pps_threshold"] + 1):
                    traffic_stats["alerts"].append({
                        "Timestamp": timestamp.strftime("%H:%M:%S"),
                        "Type": "DDoS Attack",
                        "Source": src_ip,
                        "Destination": dst_ip,
                        "Protocol": protocol,
                        "Severity": "Critical"
                    })

            # Keep alerts manageable (Increased limit for better forensic history)
            if len(traffic_stats["alerts"]) > DETECTION_CONFIG["alerts_limit"]:
                traffic_stats["alerts"].pop(0)

        except Exception as e:
            # print(f"Error processing packet: {e}") 
            pass

def run_sniffer_safely():
    """Wrapper to run Scapy sniff safely."""
    try:
        sniff(prn=process_packet, store=False)
    except Exception as e:
        print(f"Scapy sniffer disabled (driver missing): {e}")

def start_sniffer():
    """Starts the packet sniffer in a separate thread."""
    global sniffer_thread, is_running
    if not is_running:
        is_running = True
        try:
            sniffer_thread = threading.Thread(target=run_sniffer_safely)
            sniffer_thread.daemon = True
            sniffer_thread.start()
        except Exception as e:
            print(f"Scapy thread failed to start: {e}")

def get_packet_log():
    """Returns the list of captured packets."""
    with lock:
        return list(packet_data)

def process_imported_file(file_content, filename):
    """Parses uploaded file and sets imported_stats."""
    global imported_stats
    
    # Debug logging
    with open("backend_debug.log", "a") as f:
        f.write(f"[{datetime.now()}] Processing file: {filename}, Size: {len(file_content)} bytes\n")

    try:
        data = []
        filename_lower = filename.lower()
        
        # CSV Parsing
        if filename_lower.endswith('.csv'):
            try:
                df = pd.read_csv(io.BytesIO(file_content))
                df.columns = [c.lower() for c in df.columns]
                for col in df.columns:
                    if 'source' in col: df.rename(columns={col: 'Source'}, inplace=True)
                    elif 'destination' in col: df.rename(columns={col: 'Destination'}, inplace=True)
                    elif 'protocol' in col: df.rename(columns={col: 'Protocol'}, inplace=True)
                    elif 'length' in col: df.rename(columns={col: 'Length'}, inplace=True)
                    elif 'time' in col: df.rename(columns={col: 'Time'}, inplace=True)
                data = df.to_dict(orient='records')
            except Exception as e:
                 with open("backend_debug.log", "a") as f: f.write(f"CSV Error: {e}\n")
                 return {"error": f"CSV Parsing failed: {str(e)}"}

        # JSON Parsing
        elif filename_lower.endswith('.json'):
            try:
                json_data = json.load(io.BytesIO(file_content))
                if isinstance(json_data, list): data = json_data
                else: data = [json_data]
            except Exception as e:
                 with open("backend_debug.log", "a") as f: f.write(f"JSON Error: {e}\n")
                 return {"error": f"JSON Parsing failed: {str(e)}"}

        # PDF Parsing
        elif filename_lower.endswith('.pdf'):
            try:
                with pdfplumber.open(io.BytesIO(file_content)) as pdf:
                    for page in pdf.pages:
                        tables = page.extract_tables()
                        for table in tables:
                            if not table: continue
                            headers = [h.lower() if h else '' for h in table[0]]
                            for row in table[1:]:
                                if len(row) != len(headers): continue
                                row_dict = {}
                                for i, h in enumerate(headers):
                                    if 'source' in h: row_dict['Source'] = row[i]
                                    elif 'destination' in h: row_dict['Destination'] = row[i]
                                    elif 'protocol' in h: row_dict['Protocol'] = row[i]
                                    elif 'length' in h: row_dict['Length'] = row[i]
                                if row_dict:
                                    data.append(row_dict)
            except Exception as e:
                 with open("backend_debug.log", "a") as f: f.write(f"PDF Error: {e}\n")
                 return {"error": f"PDF Parsing failed: {str(e)}"}
        
        # PCAP Parsing (Streaming)
        elif filename_lower.endswith(('.pcap', '.pcapng', '.cap')):
            try:
                # Use PcapReader for streaming to avoid memory explosion
                import tempfile
                import os
                
                # Use mkstemp to fully control file handle
                fd, tmp_path = tempfile.mkstemp(suffix=".pcap")
                # Close the low-level handle first
                with os.fdopen(fd, 'wb') as tmp_file:
                    tmp_file.write(file_content)
                # Now file is definitely closed and free for Scapy to open
                
                # Initialize stats for on-the-fly aggregation
                stats = {
                    "total_packets": 0,
                    "unique_ips": set(),
                    "protocols": {},
                    "top_sources": {},
                    "top_destinations": {},
                    "packet_sizes": {"0-100": 0, "100-500": 0, "500-1000": 0, "1000+": 0},
                    "alerts": []
                }
                
                # Streaming Process
                count = 0
                try:
                    with scapy.PcapReader(tmp_path) as reader:
                        for pkt in reader:
                            count += 1
                            src = "Unknown"
                            dst = "Unknown"
                            proto = "Other"
                            length = len(pkt)
                            
                            # Real Timestamp
                            try:
                                ts = float(pkt.time)
                                timestamp_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
                            except:
                                timestamp_str = datetime.now().strftime("%H:%M:%S")

                            try:
                                # Layer extraction
                                if pkt.haslayer(IP):
                                    src = pkt[IP].src
                                    dst = pkt[IP].dst
                                    proto = "IP"
                                elif pkt.haslayer(scapy.IPv6):
                                    src = pkt[scapy.IPv6].src
                                    dst = pkt[scapy.IPv6].dst
                                    proto = "IPv6"
                                elif pkt.haslayer(scapy.ARP):
                                    src = pkt[scapy.ARP].psrc
                                    dst = pkt[scapy.ARP].pdst
                                    proto = "ARP"
                                elif pkt.haslayer(scapy.Ether):
                                    src = pkt[scapy.Ether].src
                                    dst = pkt[scapy.Ether].dst

                                # Check Application Layers First (Import Mode)
                                if pkt.haslayer(scapy.DNS): proto = "DNS"
                                elif pkt.haslayer(scapy.DHCP): proto = "DHCP"
                                elif pkt.haslayer(scapy.ARP): proto = "ARP"
                                elif pkt.haslayer(TCP): 
                                    proto = "TCP"
                                    # Try to guess app based on ports if available
                                    try:
                                        if pkt.haslayer(TCP):
                                            mapped_protocol = _protocol_from_ports("TCP", pkt[TCP].sport, pkt[TCP].dport)
                                            if mapped_protocol:
                                                proto = mapped_protocol
                                    except: pass
                                elif pkt.haslayer(UDP): 
                                    proto = "UDP"
                                    try:
                                        if pkt.haslayer(UDP):
                                            mapped_protocol = _protocol_from_ports("UDP", pkt[UDP].sport, pkt[UDP].dport)
                                            if mapped_protocol:
                                                proto = mapped_protocol
                                    except: pass
                                elif pkt.haslayer(ICMP): proto = "ICMP"
                                
                                # Aggregation
                                stats["unique_ips"].add(str(src))
                                stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1
                                stats["top_sources"][src] = stats["top_sources"].get(src, 0) + 1
                                stats["top_destinations"][dst] = stats["top_destinations"].get(dst, 0) + 1

                                stats["packet_sizes"][_classify_packet_size(length)] += 1

                                if length > DETECTION_CONFIG["import_large_packet_threshold"]:
                                     stats["alerts"].append({
                                        "Timestamp": timestamp_str,
                                        "Type": "Large Packet",
                                        "Source": src,
                                        "Protocol": proto,
                                        "Severity": "Medium"
                                    })
                            except:
                                pass
                except Exception as reader_e:
                    with open("backend_debug.log", "a") as f: f.write(f"Scapy Reader Error: {reader_e}\n")
                    # Don't return error yet, try to cleanup and return partial data? 
                    # Or just log and fail? Let's log.
                    pass

                stats["total_packets"] = count
                
                # Now it is safe to remove
                if os.path.exists(tmp_path):
                    try:
                        os.unlink(tmp_path)
                    except Exception as del_e:
                         with open("backend_debug.log", "a") as f: f.write(f"Temp file cleanup failed: {del_e}\n")
                
                imported_stats = stats
                with open("backend_debug.log", "a") as f: f.write("PCAP processed successfully.\n")
                return {"message": "File processed successfully", "stats": stats}
                
            except Exception as e:
                 with open("backend_debug.log", "a") as f: f.write(f"PCAP Error: {e}\n")
                 # Try to cleanup if we failed before the block above
                 if 'tmp_path' in locals() and os.path.exists(tmp_path):
                     try: os.unlink(tmp_path)
                     except: pass
                 return {"error": f"PCAP Parsing failed: {str(e)}"}

        # Process Extracted Data into Stats (for CSV/JSON/PDF)
        if not data:
            with open("backend_debug.log", "a") as f: f.write("No valid data found in file\n")
            return {"error": "No valid data found in file. Please check file format."}

        stats = {
            "total_packets": len(data),
            "unique_ips": set(),
            "protocols": {},
            "top_sources": {},
            "top_destinations": {},
            "packet_sizes": {"0-100": 0, "100-500": 0, "500-1000": 0, "1000+": 0},
            "alerts": []
        }

        for row in data:
            src = row.get('Source', 'Unknown')
            dst = row.get('Destination', 'Unknown')
            proto = row.get('Protocol', 'Other')
            try:
                length = int(row.get('Length', 0))
            except:
                length = 0

            stats["unique_ips"].add(str(src))
            stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1
            stats["top_sources"][src] = stats["top_sources"].get(src, 0) + 1
            stats["top_destinations"][dst] = stats["top_destinations"].get(dst, 0) + 1

            stats["packet_sizes"][_classify_packet_size(length)] += 1
            if length > DETECTION_CONFIG["import_large_packet_threshold"]:
                 stats["alerts"].append({
                    "Timestamp": "IMP",
                    "Type": "Large Packet (Imported)",
                    "Source": src,
                    "Protocol": proto,
                    "Severity": "Medium"
                })
        
        stats["total_packets"] = len(data) if data else stats["total_packets"]

        imported_stats = stats
        with open("backend_debug.log", "a") as f: f.write("File processed successfully.\n")
        return {"message": "File processed successfully", "stats": stats}

    except Exception as e:
        with open("backend_debug.log", "a") as f: f.write(f"CRITICAL ERROR: {e}\n")
        print(f"Error processing file: {e}")
        return {"error": f"Critical Processing Error: {str(e)}"}

def clear_imported_data():
    """Resets the imported stats to None, reverting to live/simulated data."""
    global imported_stats
    imported_stats = None
    return {"message": "Imported data cleared"}

def _get_effective_data():
    """Helper to get current stats from imported/live data without mock synthesis."""
    
    # Priority 1: Imported Data
    global imported_stats
    if imported_stats:
        return {
            "protocols": imported_stats["protocols"],
            "top_sources": imported_stats["top_sources"],
            "top_destinations": imported_stats["top_destinations"],
            "packet_sizes": imported_stats["packet_sizes"],
            "total_packets": imported_stats["total_packets"],
            "alerts": imported_stats["alerts"],
            "unique_ips": imported_stats["unique_ips"], # Added this
            "mode": "Imported Data Analysis"
        }

    net_io = psutil.net_io_counters()
    real_total_packets = net_io.packets_sent + net_io.packets_recv
    
    # Captured packets (Scapy) only.
    real_scapy_count = sum(traffic_stats["protocols"].values())
    
    # Default to real data
    effective_protocols = traffic_stats["protocols"].copy()
    effective_top_sources = traffic_stats["top_sources"].copy()
    effective_top_destinations = traffic_stats["top_destinations"].copy()
    effective_packet_sizes = traffic_stats["packet_sizes"].copy()
    mode = "Live Packet Capture"

    # If interface capture is unavailable but system counters move, mark visibility mode.
    if real_scapy_count == 0 and real_total_packets > 0:
        mode = "System Counters (Limited Capture Visibility)"

    # 3. Real Data Only (No Simulation of Alerts)
    effective_alerts = traffic_stats["alerts"]

    return {
        "protocols": effective_protocols,
        "top_sources": effective_top_sources,
        "top_destinations": effective_top_destinations,
        "packet_sizes": effective_packet_sizes,
        # Only show packets actually captured by the sniffer.
        "total_packets": real_scapy_count,
        "alerts": effective_alerts,
        "mode": mode
    }

def get_stats():
    """Returns the current statistics."""
    global last_total_packets
    with lock:
        data = _get_effective_data()
        
        # Track trend (Calculate Delta)
        if last_total_packets == 0:
            last_total_packets = data["total_packets"]
        
        packet_delta = data["total_packets"] - last_total_packets
        if packet_delta < 0: packet_delta = 0 
        last_total_packets = data["total_packets"]

        now = datetime.now()
        current_time_str = now.strftime("%H:%M:%S")
        traffic_trend.append(
            {
                "time": current_time_str,
                "packets": packet_delta,
                "timestamp": now.isoformat(),
            }
        )
        if len(traffic_trend) > DETECTION_CONFIG["trend_max_points"]:
            traffic_trend.pop(0)

        # Alerts logic
        display_alerts = []
        if data["mode"] == "Imported Data Analysis":
            # Use imported alerts directly
            display_alerts = list(reversed(data["alerts"]))
            # Debugging Unique IPs issue
            print(f"DEBUG IMPORT: Total Packets: {data['total_packets']}, Unique IPs: {len(data['unique_ips'])}")
        else:
            # Live/Simulated logic
            display_alerts = list(reversed(traffic_stats["alerts"]))
            # We ONLY show real alerts now. No simulation injection.

        # Add System Health Alerts (Real-time check)
        try:
            cpu_usage = psutil.cpu_percent(interval=None)
            ram_usage = psutil.virtual_memory().percent
            
            if cpu_usage > DETECTION_CONFIG["cpu_ram_critical_threshold"] or ram_usage > DETECTION_CONFIG["cpu_ram_critical_threshold"]:
                # Add to top of alerts
                display_alerts.insert(0, {
                    "Timestamp": datetime.now().strftime("%H:%M:%S"),
                    "Type": "Critical System Load",
                    "Source": "Localhost",
                    "Destination": f"CPU: {cpu_usage}%, RAM: {ram_usage}%",
                    "Protocol": "SYS",
                    "Severity": "Critical"
                })
        except:
            pass

        # Calculate System Health (Inverse of Max Load)
        try:
            current_cpu = psutil.cpu_percent(interval=None)
            current_ram = psutil.virtual_memory().percent
            health_score = max(0, 100 - max(current_cpu, current_ram))
        except:
            health_score = 0

        return {
            "total_packets": data["total_packets"],
            "unique_ips": len(traffic_stats["unique_ips"]) if data["mode"] == "Live Packet Capture" else len(data.get("unique_ips", [])), 
            "protocols": data["protocols"],
            "alerts": display_alerts,
            "traffic_trend": list(traffic_trend),
            "monitoring_mode": data["mode"],
            "system_health": int(health_score)
        }

def resolve_anomaly(src_ip, anomaly_type):
    """Removes an anomaly and applies REAL Firewall Rules on Windows."""
    global traffic_stats, imported_stats
    with lock:
        # Safety Check: Never block critical IPs
        if src_ip in ["127.0.0.1", "localhost", "0.0.0.0", "::1"] or src_ip.startswith("192.168.1.1"): 
            return {"resolved": False, "message": f"Safety Trigger: Cannot block critical IP {src_ip}!"}

        # 1. Apply Real Firewall Rule (Windows Only)
        firewall_msg = "Simulation Mode (No OS changes)"
        if platform.system() == "Windows":
            try:
                rule_name = f"Block_Anomaly_{src_ip}"
                # Use PowerShell to elevate privileges via UAC prompt
                # Start-Process netsh -ArgumentList '...' -Verb RunAs
                args = f'advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={src_ip}'
                cmd = f'powershell Start-Process netsh -ArgumentList \'{args}\' -Verb RunAs -WindowStyle Hidden'
                
                # Execute command
                subprocess.run(cmd, shell=True, check=True)
                firewall_msg = f"Windows Firewall Rule '{rule_name}' requested (Check UAC prompt)."
            except Exception as e:
                firewall_msg = f"Firewall Error: {str(e)}. (Run App as Admin)"

        # 2. Update Internal State (Dashboard)
        # Determine target (Live or Imported)
        target = imported_stats if imported_stats else traffic_stats
        
        initial_count = len(target["alerts"])
        # Keep alerts that DO NOT match the criteria
        target["alerts"] = [
            a for a in target["alerts"] 
            if not (a["Source"] == src_ip and a["Type"] == anomaly_type)
        ]
        removed = initial_count - len(target["alerts"])
        
        return {
            "resolved": True, 
            "removed_count": removed,
            "message": f"Mitigation: {firewall_msg} Resolved {removed} alerts."
        }

def get_analytics():
    """Returns detailed analytics for the Traffic Analysis page."""
    with lock:
        data = _get_effective_data()

        # Sort Top IPs
        sorted_sources = sorted(data["top_sources"].items(), key=lambda x: x[1], reverse=True)[:DETECTION_CONFIG["top_entities_limit"]]
        sorted_dests = sorted(data["top_destinations"].items(), key=lambda x: x[1], reverse=True)[:DETECTION_CONFIG["top_entities_limit"]]
        
        # Format trend
        formatted_trend = []
        if len(traffic_trend) > 1:
            # traffic_trend already has delta, just return it
            formatted_trend = list(traffic_trend)
        else:
             formatted_trend = [{"time": datetime.now().strftime("%H:%M:%S"), "packets": 0}]

        return {
            "traffic_trend": formatted_trend,
            "top_sources": [{"name": k, "value": v} for k, v in sorted_sources],
            "top_destinations": [{"name": k, "value": v} for k, v in sorted_dests],
            "protocol_breakdown": [{"name": k, "value": v} for k, v in data["protocols"].items()],
            "packet_sizes": [{"name": k, "value": v} for k, v in data["packet_sizes"].items()]
        }

def get_anomaly_stats():
    """Returns REAL anomaly statistics based on captured packet analysis."""
    with lock:
        data = _get_effective_data()
        recent_packets = list(packet_data)[-DETECTION_CONFIG["anomaly_window_size"]:]

        # 1. Calculate Frequency (Packets per IP in recent window)
        ip_counts = {}
        dst_counts = {}
        pair_counts = {}
        for pkt in recent_packets:
            src = pkt.get("Source")
            dst = pkt.get("Destination", "Unknown")
            proto = pkt.get("Protocol", "Unknown")
            ip_counts[src] = ip_counts.get(src, 0) + 1
            dst_counts[dst] = dst_counts.get(dst, 0) + 1
            pair_key = (src, dst, proto)
            pair_counts[pair_key] = pair_counts.get(pair_key, 0) + 1
        
        # Normalize frequency to 0-100 scale for Y-axis
        max_freq = max(ip_counts.values()) if ip_counts else 1
        max_dst_freq = max(dst_counts.values()) if dst_counts else 1
        max_pair_freq = max(pair_counts.values()) if pair_counts else 1

        # 2. Identify Active Threats IPs
        threat_ips = set()
        for alert in data["alerts"]:
            threat_ips.add(alert["Source"])

        # 3. Generate Real Scatter Data
        scatter_data = []
        scores = []
        
        for pkt in recent_packets:
            src = pkt.get("Source")
            dst = pkt.get("Destination", "Unknown")
            proto = pkt.get("Protocol", "Unknown")
            length = pkt.get("Length", 0)
            
            # Simple "Anomaly Score" based on Frequency + Threat Status
            freq = ip_counts.get(src, 0)
            normalized_freq = (freq / max_freq) * 100
            
            is_threat = src in threat_ips
            
            # Type classification
            point_type = "Normal"
            if is_threat:
                point_type = "Anomaly"
            elif length > DETECTION_CONFIG["import_large_packet_threshold"]:
                point_type = "Anomaly"
            
            score = _compute_anomaly_score(
                freq=freq,
                max_freq=max_freq,
                packet_length=length,
                severity="High" if is_threat else "Low",
                is_threat=is_threat,
                protocol=proto,
                destination_freq=dst_counts.get(dst, 0),
                max_destination_freq=max_dst_freq,
                pair_freq=pair_counts.get((src, dst, proto), 0),
                max_pair_freq=max_pair_freq,
            )
            scatter_data.append({
                "x": length,            # Real Packet Size
                "y": normalized_freq,   # Real Frequency
                "type": point_type,
                "score": score
            })
            scores.append(score)

        # 4. Real Score Distribution
        score_dist = [
            {"range": "0.0-0.2", "count": 0},
            {"range": "0.2-0.4", "count": 0},
            {"range": "0.4-0.6", "count": 0},
            {"range": "0.6-0.8", "count": 0},
            {"range": "0.8-1.0", "count": 0}
        ]
        
        for s in scores:
            if s <= 0.2: score_dist[0]["count"] += 1
            elif s <= 0.4: score_dist[1]["count"] += 1
            elif s <= 0.6: score_dist[2]["count"] += 1
            elif s <= 0.8: score_dist[3]["count"] += 1
            else: score_dist[4]["count"] += 1

        # 5. Risk Calculation (Real) with Normalization (0-100 Scale)
        high_sev_count = len([a for a in data["alerts"] if a['Severity'] in ['High', 'Critical']])
        raw_score = len(data["alerts"]) + (high_sev_count * 50)
        
        low_threshold = DETECTION_CONFIG["risk_low_threshold"]
        medium_threshold = DETECTION_CONFIG["risk_medium_threshold"]
        low_scale = DETECTION_CONFIG["risk_low_scale_max"]
        medium_scale = DETECTION_CONFIG["risk_medium_scale_max"]
        high_scale = DETECTION_CONFIG["risk_high_scale_max"]
        
        normalized_score = 0
        risk_level = "Low"
        
        if raw_score < low_threshold:
            risk_level = "Low"
            normalized_score = (raw_score / max(1, low_threshold)) * low_scale
        elif raw_score < medium_threshold:
            risk_level = "Medium"
            mid_span = max(1, medium_threshold - low_threshold)
            normalized_score = low_scale + ((raw_score - low_threshold) / mid_span) * (medium_scale - low_scale)
        else:
            risk_level = "High"
            high_span = max(1, medium_threshold)
            normalized_score = medium_scale + ((raw_score - medium_threshold) / high_span) * (high_scale - medium_scale)
            
        risk_score = int(min(high_scale, normalized_score))
        
        # 6. Real Forensics Table (Enriching the alerts)
        forensics = []
        action_map = {"Low": "Logged", "Medium": "Flagged", "High": "Alerted", "Critical": "Blocked"}
        
        for alert in data["alerts"]:
            severity = alert["Severity"]
            src = alert["Source"]
            dst = alert.get("Destination", "Multiple Targets")
            protocol = _normalize_protocol(alert["Type"], alert.get("Protocol", "Unknown"))
            freq = ip_counts.get(src, 0)
            avg_length = 0
            matched_lengths = [
                pkt.get("Length", 0)
                for pkt in recent_packets
                if pkt.get("Source") == src and pkt.get("Destination", "Unknown") == dst and pkt.get("Protocol", "Unknown") == protocol
            ]
            if not matched_lengths:
                matched_lengths = [
                    pkt.get("Length", 0)
                    for pkt in recent_packets
                    if pkt.get("Source") == src and pkt.get("Destination", "Unknown") == dst
                ]
            if not matched_lengths:
                matched_lengths = [pkt.get("Length", 0) for pkt in recent_packets if pkt.get("Source") == src]
            if matched_lengths:
                avg_length = sum(matched_lengths) / len(matched_lengths)
            anomaly_score = _compute_anomaly_score(
                freq=freq,
                max_freq=max_freq,
                packet_length=avg_length,
                severity=severity,
                is_threat=True,
                protocol=protocol,
                destination_freq=dst_counts.get(dst, 0),
                max_destination_freq=max_dst_freq,
                pair_freq=pair_counts.get((src, dst, protocol), 0),
                max_pair_freq=max_pair_freq,
            )
            forensics.append({
                "timestamp": alert["Timestamp"],
                "source_ip": src,
                "destination_ip": dst, # Use Real Destination
                "protocol": protocol,
                "anomaly_score": round(anomaly_score, 4),
                "severity": severity,
                "type": alert["Type"],
                "action_taken": action_map.get(severity, "Logged")
            })

        return {
            "summary": {
                "total_anomalies": len(data["alerts"]),
                "anomaly_percentage": f"{(len(data['alerts']) / max(1, data['total_packets']) * 100):.4f}%",
                "high_severity_count": high_sev_count,
                "risk_level": risk_level,
                "risk_score": risk_score
            },
            "scatter_data": scatter_data, # Now Real
            "score_distribution": score_dist, # Now Real
            "threat_distribution": [{"name": k, "count": v} for k, v in {t["Type"]: len([x for x in data["alerts"] if x["Type"] == t["Type"]]) for t in data["alerts"]}.items()],
            "forensics": list(reversed(forensics)) # Now Real
        }

def get_forensic_stats():
    """Returns REAL detailed forensic investigation data from captured alerts."""
    with lock:
        data = _get_effective_data()
        
        # 1. Case Info
        case_id = f"INV-{datetime.now().strftime('%Y%m%d')}-REAL"
        
        # 2. Enrich Logs for Forensics (Use REAL data)
        logs = []
        action_map = {"Low": "Logged", "Medium": "Flagged", "High": "Alerted", "Critical": "Blocked"}
        
        # CRITICAL FIX: If no imported data is active, FORCE use of LIVE traffic stats
        # This prevents empty imported_stats from hiding live alerts
        global imported_stats
        if imported_stats is None:
             filtered_alerts = traffic_stats["alerts"]
        else:
             filtered_alerts = data["alerts"]

        print(f"DEBUG: Forensics Fetch - Mode: {data.get('mode', 'Unk')} | Count (Live): {len(traffic_stats['alerts'])} | Count (Used): {len(filtered_alerts)}")
        
        src_counts = {}
        src_lengths = {}
        for pkt in packet_data[-DETECTION_CONFIG["anomaly_window_size"]:]:
            src = pkt.get("Source")
            if not src:
                continue
            src_counts[src] = src_counts.get(src, 0) + 1
            src_lengths.setdefault(src, []).append(pkt.get("Length", 0))
        max_src_freq = max(src_counts.values()) if src_counts else 1

        for alert in filtered_alerts:
            severity = alert["Severity"]
            src_ip = alert["Source"]
            avg_len = 0
            if src_ip in src_lengths and src_lengths[src_ip]:
                avg_len = sum(src_lengths[src_ip]) / len(src_lengths[src_ip])
            anomaly_score = _compute_anomaly_score(
                freq=src_counts.get(src_ip, 0),
                max_freq=max_src_freq,
                packet_length=avg_len,
                severity=severity,
                is_threat=True,
            )
            # Use real destination if available, else generic
            real_dst = alert.get("Destination", "Multiple Targets")
            
            logs.append({
                "timestamp": alert["Timestamp"],
                "source_ip": src_ip,
                "destination_ip": real_dst,
                "protocol": _normalize_protocol(alert["Type"], alert.get("Protocol", "Unknown")),
                "attack_type": alert["Type"],
                "packet_size": "Var", # We don't store exact size in alert summary yet
                "anomaly_score": round(anomaly_score, 4),
                "severity": severity,
                "action_taken": action_map.get(severity, "Logged")
            })
            
        # 3. Real Timeline Data
        # Aggregate alerts by minute (or 10-second buckets)
        timeline_buckets = {}
        
        # Check if we are using imported data
        # global imported_stats (Already declared at top of function)
        is_imported = imported_stats is not None

        if not is_imported:
            # Live Mode: Initialize last 10 minutes relative to NOW
            now = datetime.now()
            for i in range(DETECTION_CONFIG["live_timeline_minutes"]):
                t_key = (now - timedelta(minutes=i)).strftime("%H:%M")
                timeline_buckets[t_key] = 0
        # Else (Imported Mode): Do not pre-fill. Let the data define the timeline.

        # Fill with actual data
        for alert in filtered_alerts:
            ts_val = alert.get("Timestamp", "")
            ts_str = ""
            
            try:
                # Handle Datetime object vs String
                if hasattr(ts_val, 'strftime'):
                    ts_str = ts_val.strftime("%H:%M")
                elif isinstance(ts_val, str):
                    if " " in ts_val:
                        # Format: "YYYY-MM-DD HH:MM:SS" -> Extract "HH:MM"
                        try:
                             ts_str = ts_val.split(" ")[1][:5]
                        except:
                             ts_str = ts_val[:5]
                    elif len(ts_val) >= 5:
                        ts_str = ts_val[:5] # "HH:MM"
                
                if ts_str:
                    timeline_buckets[ts_str] = timeline_buckets.get(ts_str, 0) + 1
            except Exception as e:
                pass
                
        # Convert to list and sort
        timeline = []
        for time_key in sorted(timeline_buckets.keys()):
             timeline.append({
                "time": time_key,
                "incidents": timeline_buckets[time_key],
                "severity_score": timeline_buckets[time_key] * DETECTION_CONFIG["timeline_severity_multiplier"]
            })
        
        # Ensure we only return last 10 points (Live) or All relevant points (Imported)
        if len(timeline) > DETECTION_CONFIG["timeline_max_points"]:
             # If too many points, take the ones with most activity or just the last ones?
             # For now, let's show more data, e.g., last 20 points
             timeline = timeline[-DETECTION_CONFIG["timeline_max_points"]:]

        # Stats
        threat_counts = {}
        for l in logs:
            threat_counts[l["attack_type"]] = threat_counts.get(l["attack_type"], 0) + 1
        most_active_threat = max(threat_counts, key=threat_counts.get) if threat_counts else "None"

        time_range = "N/A"
        if timeline:
             time_range = f"{timeline[0]['time']} - {timeline[-1]['time']}"

        return {
            "case_info": {
                "id": case_id,
                "time_range": time_range,
                "total_incidents": len(logs),
                "critical_events": len([l for l in logs if l['severity'] in ['High', 'Critical']]),
                "most_active_threat": most_active_threat
            },
            "timeline": timeline,
            "logs": list(reversed(logs))
        }

def get_full_report_stats():
    """Aggregates all metrics for the Comprehensive Security Report."""
    # lock removed to prevent starvation/deadlock. Child functions manage their own locks.
    data = _get_effective_data()
    anomaly_data = get_anomaly_stats()
    forensic_data = get_forensic_stats()
        
    # 1. Header Info
    report_id = f"REP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    gen_time = datetime.now().strftime("%d-%m-%Y")
    time_range = f"00:00 - {datetime.now().strftime('%H:%M')}"
    
    # 2. Incident Summary
    total_traffic = data["total_packets"]
    total_anomalies = forensic_data["case_info"]["total_incidents"]
    risk_level = anomaly_data["summary"]["risk_level"]
    
    # 3. Threat Analysis
    threat_counts = {}
    for alert in data["alerts"]:
        threat_counts[alert["Type"]] = threat_counts.get(alert["Type"], 0) + 1
        
    top_threat = max(threat_counts, key=threat_counts.get) if threat_counts else "None"

    dominant_protocol = _get_dominant_protocol(data["protocols"])
    packet_size_summary = _get_packet_size_summary(data["packet_sizes"])
    peak_time = _get_peak_time(traffic_trend)

    source_alert_counts = {}
    severity_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    highest_severity = "Low"
    for alert in data["alerts"]:
        src = alert.get("Source", "Unknown")
        source_alert_counts[src] = source_alert_counts.get(src, 0) + 1
        sev = alert.get("Severity", "Low")
        if severity_rank.get(sev, 0) > severity_rank.get(highest_severity, 0):
            highest_severity = sev

    suspicious_ip = max(source_alert_counts, key=source_alert_counts.get) if source_alert_counts else "None"
    action_map = {"Low": "Logged", "Medium": "Flagged", "High": "Alerted", "Critical": "Blocked"}
    action_taken = action_map.get(highest_severity, "Logged")

    try:
        cpu_now = psutil.cpu_percent(interval=None)
        ram_now = psutil.virtual_memory().percent
        system_health = f"{int(max(0, 100 - max(cpu_now, ram_now)))}%"
    except Exception:
        system_health = "N/A"
    
    # 4. Standout attributes for clear reporting
    key_findings = [
        {"label": "Overall Risk Level", "value": risk_level, "priority": "Critical" if risk_level == "High" else "High"},
        {"label": "Most Suspicious IP", "value": suspicious_ip, "priority": "High" if suspicious_ip != "None" else "Medium"},
        {"label": "Primary Attack Type", "value": top_threat, "priority": "High" if top_threat != "None" else "Medium"},
        {"label": "Critical Alerts", "value": forensic_data["case_info"]["critical_events"], "priority": "High"},
        {"label": "Dominant Protocol", "value": dominant_protocol, "priority": "Medium"},
        {"label": "Action Taken", "value": action_taken, "priority": "High" if action_taken in ["Blocked", "Alerted"] else "Medium"},
    ]

    # 5. Recommendations
    recommendations = [
        f"Monitor Gateway Traffic for {top_threat} patterns",
        "Enable IDS alerts for UDP flood attempts",
        "Review firewall rules for Port 80/443"
    ]
    if "High" in risk_level or "Critical" in risk_level:
        recommendations.insert(0, f"IMMEDIATE ACTION: Block High Risk IPs associated with {top_threat}")

    return {
        "header": {
            "title": "Comprehensive Security Investigation Report",
            "report_id": report_id,
            "generated_on": gen_time,
            "time_range": time_range,
            "system_health": system_health
        },
        "summary": {
            "total_packets": f"{total_traffic:,} packets",
            "total_anomalies": total_anomalies,
            "anomaly_percentage": anomaly_data["summary"]["anomaly_percentage"],
            "critical_alerts": forensic_data["case_info"]["critical_events"],
            "risk_level": risk_level
        },
        "threats": {
            "top_threat": top_threat,
            "distribution": [{"name": k, "count": v} for k, v in threat_counts.items()]
        },
        "traffic": {
            "peak_time": peak_time,
            "dominant_protocol": dominant_protocol,
            "packet_size_summary": packet_size_summary
        },
        "forensics": {
            "suspicious_ip": suspicious_ip,
            "total_incidents": total_anomalies,
            "primary_attack": top_threat,
            "action_taken": action_taken
        },
        "key_findings": key_findings,
        "evidence": forensic_data["logs"],
        "recommendations": recommendations
    }


