import sys
import traceback

print("Starting Diagnostics...")
try:
    from backend import sniffer
    print("Import Successful.")
    
    print("Testing get_stats()...")
    sniffer.get_stats()
    print("get_stats() OK.")

    print("Testing get_anomaly_stats()...")
    sniffer.get_anomaly_stats()
    print("get_anomaly_stats() OK.")

    print("Testing get_forensic_stats()...")
    sniffer.get_forensic_stats()
    print("get_forensic_stats() OK.")

    print("Testing get_full_report_stats()...")
    sniffer.get_full_report_stats()
    print("get_full_report_stats() OK.")

except Exception:
    traceback.print_exc()
