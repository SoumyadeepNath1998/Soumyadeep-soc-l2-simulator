"""
SOC L2 Simulator - Module 4: BlueCat IPAM & Asset Attribution Engine
Performs IP-to-Asset resolution, subnet zoning, regional blast radius mapping,
and asset criticality scoring for incident triage.
"""

from typing import Dict, Any
import ipaddress

class BlueCatIPAM:
    def __init__(self):
        # Generic Global Enterprise Subnet Mapping & IPAM Database
        self.subnet_database = [
            {
                "subnet": "10.45.12.0/24",
                "zone_name": "CORP-WKS-LON-VLAN12",
                "region": "EMEA - London HQ",
                "environment": "Corporate Workstations",
                "criticality": "Tier-3 (Standard User)",
                "contact_admin": "lon-infra-ops@global-secops.com"
            },
            {
                "subnet": "10.100.4.0/24",
                "zone_name": "PROD-DB-CLUSTER-SG",
                "region": "APAC - Singapore Datacenter",
                "environment": "Core Production Databases",
                "criticality": "Tier-1 (Mission Critical)",
                "contact_admin": "sg-dba-team@global-secops.com"
            },
            {
                "subnet": "172.16.50.0/24",
                "zone_name": "OT-MANUFACTURING-US",
                "region": "NA - Industrial Plant",
                "environment": "Operational Technology / SCADA",
                "criticality": "Tier-1 (High - Manufacturing Safety)",
                "contact_admin": "ot-sec-ops@global-secops.com"
            },
            {
                "subnet": "192.168.10.0/24",
                "zone_name": "VPN-POOL-GLOBAL",
                "region": "Global Remote Access",
                "environment": "GlobalProtect VPN Pool",
                "criticality": "Tier-2 (Remote Ingress)",
                "contact_admin": "netops-global@global-secops.com"
            }
        ]

    def lookup_ip_attribution(self, target_ip: str) -> Dict[str, Any]:
        """
        Resolves internal enterprise IP against BlueCat IPAM allocation records.
        """
        try:
            ip_obj = ipaddress.ip_address(target_ip)
        except ValueError:
            return {
                "ip": target_ip,
                "status": "INVALID_IP_FORMAT",
                "is_internal": False
            }

        if not ip_obj.is_private:
            return {
                "ip": target_ip,
                "status": "EXTERNAL_PUBLIC_IP",
                "is_internal": False,
                "note": "Public Routable IP - Evaluate with Threat Intelligence feeds."
            }

        for record in self.subnet_database:
            network = ipaddress.ip_network(record["subnet"])
            if ip_obj in network:
                is_p1_eligible = "Tier-1" in record["criticality"]
                return {
                    "ip": target_ip,
                    "status": "ATTRIBUTED_INTERNAL_ASSET",
                    "is_internal": True,
                    "subnet": record["subnet"],
                    "vlan_zone": record["zone_name"],
                    "region": record["region"],
                    "environment_type": record["environment"],
                    "asset_criticality": record["criticality"],
                    "sla_escalation_flag": is_p1_eligible,
                    "responsible_team": record["contact_admin"],
                    "containment_caution": "DO NOT ISOLATE AUTOMATICALLY - REQUIRES L3 & STAKEHOLDER SIGN-OFF" if is_p1_eligible else "SAFE_TO_CONTAIN"
                }

        return {
            "ip": target_ip,
            "status": "UNMAPPED_INTERNAL_IP",
            "is_internal": True,
            "asset_criticality": "Tier-3 (Unregistered Subnet)",
            "sla_escalation_flag": False,
            "containment_caution": "SAFE_TO_CONTAIN"
        }