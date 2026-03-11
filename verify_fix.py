import sys
import traceback
from backend import sniffer

print("Verifying Deadlock Fix...")
try:
    # This previously caused a deadlock
    print("Attempting to generate Full Report...")
    report = sniffer.get_full_report_stats()
    print("SUCCESS: Report Generated!")
    print(f"Report ID: {report['header']['report_id']}")
    print("Deadlock is FIXED on disk.")
except Exception:
    traceback.print_exc()
