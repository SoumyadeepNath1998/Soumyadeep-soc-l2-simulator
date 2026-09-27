import json
from bluecat_ipam import BlueCatIPAM

ipam = BlueCatIPAM()

# Test 1: Standard London Corporate Workstation
ip1 = "10.45.12.89"
print(f"=== Attribution for IP: {ip1} ===")
print(json.dumps(ipam.lookup_ip_attribution(ip1), indent=2))

# Test 2: Mission-Critical Production Database in Singapore (Tier-1)
ip2 = "10.100.4.25"
print(f"\n=== Attribution for IP: {ip2} (Critical Asset) ===")
print(json.dumps(ipam.lookup_ip_attribution(ip2), indent=2))

# Test 3: Public Malicious External C2 IP
ip3 = "185.220.101.5"
print(f"\n=== Attribution for IP: {ip3} (External IOC) ===")
print(json.dumps(ipam.lookup_ip_attribution(ip3), indent=2))