from scapy.all import get_if_list, get_working_ifaces, conf

print("Scapy Interface Diagnostic")
print("==========================")

print("\n1. All Interfaces (Names):")
print(get_if_list())

print("\n2. Working Interfaces (Scapy):")
try:
    for iface in get_working_ifaces():
        print(f" - {iface.name} ({iface.ip}) [{iface.mac}]")
except Exception as e:
    print(f"Error getting working ifaces: {e}")

print("\n3. Default Interface for Internet (Route to 8.8.8.8):")
try:
    default_iface = conf.route.route("8.8.8.8")[1]
    print(f" -> {default_iface}")
except Exception as e:
    print(f"Error determining default route: {e}")
