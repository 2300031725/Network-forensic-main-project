import psutil
import os
import signal

print("Scanning for zombie Python/Uvicorn processes...")
killed_count = 0

for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
    try:
        # Check if process is python and running our backend
        if proc.info['name'] == 'python.exe' or proc.info['name'] == 'uvicorn.exe':
            cmdline = proc.info.get('cmdline', [])
            if cmdline and ('backend.main:app' in str(cmdline) or 'sniffer.py' in str(cmdline)):
                print(f"Killing Process {proc.info['pid']} ({cmdline})...")
                proc.kill()
                killed_count += 1
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

if killed_count > 0:
    print(f"Successfully killed {killed_count} stale processes.")
else:
    print("No stale processes found.")
