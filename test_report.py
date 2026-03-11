import sys
import threading
from backend import sniffer

print("Starting Independent Test...")
try:
    # Manually populate some data since sniffer isn't running
    sniffer.traffic_stats["total_packets"] = 100
    sniffer.traffic_stats["alerts"].append({"Timestamp": "10:00", "Type": "Test", "Severity": "High", "Source": "1.2.3.4"})
    
    print("Calling get_full_report_stats()...")
    report = sniffer.get_full_report_stats()
    print("SUCCESS: Report Generated!")
    print(report["header"])
except Exception as e:
    print(f"FAILED: {e}")
