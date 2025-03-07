import json
import logging
import os
from prettytable import PrettyTable
import meraki
import csv
from sklearn.ensemble import IsolationForest
import pandas as pd
import shutil
import traceback
from ai_analysis import (
    extract_non_compliant_data,
    detect_meraki_anomalies,
    generate_compliance_recommendations
)

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')



def load_json(filepath):
    """Load JSON data from a file."""
    with open(filepath, 'r') as file:
        return json.load(file)

def save_prettytable_to_file(table, filepath):
    """Save a PrettyTable to a file."""
    logging.debug(f"Saving PrettyTable to file: {filepath}")
    with open(filepath, 'w') as file:
        file.write(table.get_string())
    logging.debug(f"Table saved to {filepath}")


def save_dict_to_csv(data, filepath):
    with open(filepath, 'w', newline='') as file:
        writer = csv.writer(file)
        for key, value in data.items():
            writer.writerow([key, json.dumps(value)])

def flatten_dict(d, parent_key='', sep='_'):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            for i, item in enumerate(v):
                items.extend(flatten_dict({f"{new_key}_{i}": item}, '', sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def deep_compare(golden_data, network_data, path="", skip_keys=None):
    if skip_keys is None:
        skip_keys = []

    if isinstance(golden_data, dict) and isinstance(network_data, dict):
        if golden_data.keys() != network_data.keys():
            logging.debug(f"Difference found at {path}: Keys do not match")
            return False
        for key in golden_data:
            if key in skip_keys and key != 'publicIp': # Ensure publicIp is always compared
                continue
            if key == 'lanIp':  # Skip lanIp comparison for One-to-One NAT
                continue
            if not deep_compare(golden_data[key], network_data[key], path + f".{key}", skip_keys):
                return False
        return True
    elif isinstance(golden_data, list) and isinstance(network_data, list):
        if len(golden_data) != len(network_data):
            logging.debug(f"Difference found at {path}: List lengths do not match")
            return False
        for index, (item1, item2) in enumerate(zip(golden_data, network_data)):
            if not deep_compare(item1, item2, path + f"[{index}]", skip_keys):
                return False
        return True
    else:
        if golden_data != network_data:
            logging.debug(f"Difference found at {path}: {golden_data} != {network_data}")
            return False
    return True
def compare_cellular_firewall_rules(golden_config, network_config, source_octet=1, dest_octet=1):
    """Compare cellular firewall rules."""
    logging.debug(f"Comparing Cellular Firewall Rules: Golden: {golden_config}, Network: {network_config}")
    
    golden_rules = golden_config.get('firewallfirewallcelluarfirewallrules', {}).get('rules', [])
    network_rules = network_config.get('firewallfirewallcelluarfirewallrules', {}).get('rules', [])
    
    # First check if the rule count matches
    if len(golden_rules) != len(network_rules):
        logging.debug(f"Non-compliant due to rule count mismatch: Golden: {len(golden_rules)}, Network: {len(network_rules)}")
        return False
    
    # Compare each rule
    for golden_rule, network_rule in zip(golden_rules, network_rules):
        # Compare source CIDR with octet precision
        golden_src_ip = golden_rule.get('srcCidr', 'Any')
        network_src_ip = network_rule.get('srcCidr', 'Any')
        
        if golden_src_ip != 'Any' and network_src_ip != 'Any':
            golden_src_octets = golden_src_ip.split('/')[0].split('.')[:source_octet]
            network_src_octets = network_src_ip.split('/')[0].split('.')[:source_octet]
            
            if golden_src_octets != network_src_octets:
                logging.debug(f"Non-compliant due to source IP mismatch: Golden: {golden_src_ip}, Network: {network_src_ip}")
                return False
        elif golden_src_ip != network_src_ip:
            logging.debug(f"Non-compliant due to source IP type mismatch: Golden: {golden_src_ip}, Network: {network_src_ip}")
            return False
        
        # Compare destination CIDR with octet precision
        golden_dest_ip = golden_rule.get('destCidr', 'Any')
        network_dest_ip = network_rule.get('destCidr', 'Any')
        
        if golden_dest_ip != 'Any' and network_dest_ip != 'Any':
            golden_dest_octets = golden_dest_ip.split('/')[0].split('.')[:dest_octet]
            network_dest_octets = network_dest_ip.split('/')[0].split('.')[:dest_octet]
            
            if golden_dest_octets != network_dest_octets:
                logging.debug(f"Non-compliant due to destination IP mismatch: Golden: {golden_dest_ip}, Network: {network_dest_ip}")
                return False
        elif golden_dest_ip != network_dest_ip:
            logging.debug(f"Non-compliant due to destination IP type mismatch: Golden: {golden_dest_ip}, Network: {network_dest_ip}")
            return False
        
        # Compare other fields
        for field in ['policy', 'protocol', 'srcPort', 'destPort', 'syslogEnabled', 'comment']:
            if golden_rule.get(field) != network_rule.get(field):
                logging.debug(f"Non-compliant due to {field} mismatch: Golden: {golden_rule.get(field)}, Network: {network_rule.get(field)}")
                return False
    
    return True

def compare_inbound_firewall_rules(golden_config, network_config, source_octet=1, dest_octet=1):
    """Compare inbound firewall rules."""
    logging.debug(f"Comparing Inbound Firewall Rules: Golden: {golden_config}, Network: {network_config}")
    
    golden_rules = golden_config.get('firewallinboundfirewallrules', {}).get('rules', [])
    network_rules = network_config.get('firewallinboundfirewallrules', {}).get('rules', [])
    
    # First check if the rule count matches
    if len(golden_rules) != len(network_rules):
        logging.debug(f"Non-compliant due to rule count mismatch: Golden: {len(golden_rules)}, Network: {len(network_rules)}")
        return False
    
    # Compare each rule
    for golden_rule, network_rule in zip(golden_rules, network_rules):
        # Compare source CIDR with octet precision
        golden_src_ip = golden_rule.get('srcCidr', 'Any')
        network_src_ip = network_rule.get('srcCidr', 'Any')
        
        if golden_src_ip != 'Any' and network_src_ip != 'Any':
            golden_src_octets = golden_src_ip.split('/')[0].split('.')[:source_octet]
            network_src_octets = network_src_ip.split('/')[0].split('.')[:source_octet]
            
            if golden_src_octets != network_src_octets:
                logging.debug(f"Non-compliant due to source IP mismatch: Golden: {golden_src_ip}, Network: {network_src_ip}")
                return False
        elif golden_src_ip != network_src_ip:
            logging.debug(f"Non-compliant due to source IP type mismatch: Golden: {golden_src_ip}, Network: {network_src_ip}")
            return False
        
        # Compare destination CIDR with octet precision
        golden_dest_ip = golden_rule.get('destCidr', 'Any')
        network_dest_ip = network_rule.get('destCidr', 'Any')
        
        if golden_dest_ip != 'Any' and network_dest_ip != 'Any':
            golden_dest_octets = golden_dest_ip.split('/')[0].split('.')[:dest_octet]
            network_dest_octets = network_dest_ip.split('/')[0].split('.')[:dest_octet]
            
            if golden_dest_octets != network_dest_octets:
                logging.debug(f"Non-compliant due to destination IP mismatch: Golden: {golden_dest_ip}, Network: {network_dest_ip}")
                return False
        elif golden_dest_ip != network_dest_ip:
            logging.debug(f"Non-compliant due to destination IP type mismatch: Golden: {golden_dest_ip}, Network: {network_dest_ip}")
            return False
        
        # Compare other fields
        for field in ['policy', 'protocol', 'srcPort', 'destPort', 'syslogEnabled', 'comment']:
            if golden_rule.get(field) != network_rule.get(field):
                logging.debug(f"Non-compliant due to {field} mismatch: Golden: {golden_rule.get(field)}, Network: {network_rule.get(field)}")
                return False
    
    return True
def compare_one_to_one_nat_rules(golden_config, network_config, lan_ip_octet=1):
    """Compare one-to-one NAT rules."""
    logging.debug(f"Comparing One-to-One NAT Rules: Golden: {golden_config}, Network: {network_config}")
    
    golden_rules = golden_config.get('firewallonetonatone', {}).get('rules', [])
    network_rules = network_config.get('firewallonetonatone', {}).get('rules', [])
    
    # First check if the rule count matches
    if len(golden_rules) != len(network_rules):
        logging.debug(f"Non-compliant due to rule count mismatch: Golden: {len(golden_rules)}, Network: {len(network_rules)}")
        return False
    
    # Compare each rule
    for golden_rule, network_rule in zip(golden_rules, network_rules):
        # Compare uplink and name
        for field in ['uplink', 'name']:
            if golden_rule.get(field) != network_rule.get(field):
                logging.debug(f"Non-compliant due to {field} mismatch: Golden: {golden_rule.get(field)}, Network: {network_rule.get(field)}")
                return False
        
        # Compare LAN IP with octet precision
        golden_lan_ip = golden_rule.get('lanIp', '')
        network_lan_ip = network_rule.get('lanIp', '')
        
        golden_lan_octets = golden_lan_ip.split('.')[:lan_ip_octet]
        network_lan_octets = network_lan_ip.split('.')[:lan_ip_octet]
        
        if golden_lan_octets != network_lan_octets:
            logging.debug(f"Non-compliant due to LAN IP mismatch: Golden: {golden_lan_ip}, Network: {network_lan_ip}")
            return False
        
        # Compare public IP
        if golden_rule.get('publicIp') != network_rule.get('publicIp'):
            logging.debug(f"Non-compliant due to public IP mismatch: Golden: {golden_rule.get('publicIp')}, Network: {network_rule.get('publicIp')}")
            return False
        
        # Compare allowed
        if golden_rule.get('allowed') != network_rule.get('allowed'):
            logging.debug(f"Non-compliant due to allowed mismatch: Golden: {golden_rule.get('allowed')}, Network: {network_rule.get('allowed')}")
            return False
    
    return True
def compare_content_filtering(golden_config, network_config):
    """Compare content filtering settings."""
    logging.debug(f"Comparing Content Filtering: Golden: {golden_config}, Network: {network_config}")
    
    golden_cf = golden_config.get('contentfiltering', {})
    network_cf = network_config.get('contentfiltering', {})
    
    # Compare allowed URLs
    golden_allowed = set(golden_cf.get('allowedUrlPatterns', []))
    network_allowed = set(network_cf.get('allowedUrlPatterns', []))
    if golden_allowed != network_allowed:
        logging.debug(f"Non-compliant due to allowed URL patterns mismatch: Golden: {golden_allowed}, Network: {network_allowed}")
        return False
    
    # Compare blocked URLs
    golden_blocked = set(golden_cf.get('blockedUrlPatterns', []))
    network_blocked = set(network_cf.get('blockedUrlPatterns', []))
    if golden_blocked != network_blocked:
        logging.debug(f"Non-compliant due to blocked URL patterns mismatch: Golden: {golden_blocked}, Network: {network_blocked}")
        return False
    
    # Compare categories
    golden_categories = {cat['id'] for cat in golden_cf.get('blockedUrlCategories', [])}
    network_categories = {cat['id'] for cat in network_cf.get('blockedUrlCategories', [])}
    if golden_categories != network_categories:
        logging.debug(f"Non-compliant due to blocked categories mismatch: Golden: {golden_categories}, Network: {network_categories}")
        return False
    
    return True

def compare_port_forwarding_rules(golden_config, network_config, lan_ip_octet=1):
    """Compare port forwarding rules."""
    logging.debug(f"Comparing Port Forwarding Rules: Golden: {golden_config}, Network: {network_config}")
    
    golden_rules = golden_config.get('firewallportforward', {}).get('rules', [])
    network_rules = network_config.get('firewallportforward', {}).get('rules', [])
    
    # First check if the rule count matches
    if len(golden_rules) != len(network_rules):
        logging.debug(f"Non-compliant due to rule count mismatch: Golden: {len(golden_rules)}, Network: {len(network_rules)}")
        return False
    
    # Compare each rule
    for golden_rule, network_rule in zip(golden_rules, network_rules):
        # Compare LAN IP with octet precision
        golden_lan_ip = golden_rule.get('lanIp', '')
        network_lan_ip = network_rule.get('lanIp', '')
        
        golden_lan_octets = golden_lan_ip.split('.')[:lan_ip_octet]
        network_lan_octets = network_lan_ip.split('.')[:lan_ip_octet]
        
        if golden_lan_octets != network_lan_octets:
            logging.debug(f"Non-compliant due to LAN IP mismatch: Golden: {golden_lan_ip}, Network: {network_lan_ip}")
            return False
        
        # Compare other fields
        for field in ['name', 'protocol', 'publicPort', 'localPort', 'allowedIps', 'uplink']:
            if golden_rule.get(field) != network_rule.get(field):
                logging.debug(f"Non-compliant due to {field} mismatch: Golden: {golden_rule.get(field)}, Network: {network_rule.get(field)}")
                return False
    
    return True
def compare_one_to_one_nat_ips(golden_ip, network_ip, octet):
    golden_octets = golden_ip.split('.')
    network_octets = network_ip.split('.')
    result = golden_octets[:octet] == network_octets[:octet]
    logging.debug(f"Comparing One-to-One NAT IPs: Golden: {golden_ip}, Network: {network_ip}, Octets: {octet}, Result: {result}")
    logging.debug(f"Golden Octets: {golden_octets[:octet]}, Network Octets: {network_octets[:octet]}")
    return result

def compare_one_to_many_nat_rules(golden_config, network_config, one_to_many_nat_lan_ip_octet):
    """Compare one-to-many NAT rules."""
    logging.debug(f"Comparing One-to-Many NAT Rules: Golden: {golden_config}, Network: {network_config}")
    
    golden_rules = golden_config.get('firewallonetomanynatrules', {}).get('rules', [])
    network_rules = network_config.get('firewallonetomanynatrules', {}).get('rules', [])
    
    # First check if the rule count matches
    if len(golden_rules) != len(network_rules):
        logging.debug(f"Non-compliant due to rule count mismatch: Golden: {len(golden_rules)}, Network: {len(network_rules)}")
        return False
    
    # If both have zero rules, they are compliant
    if len(golden_rules) == 0 and len(network_rules) == 0:
        return True
    
    # Compare each rule
    for golden_rule, network_rule in zip(golden_rules, network_rules):
        # Check if either is None
        if golden_rule is None and network_rule is None:
            continue
        elif golden_rule is None or network_rule is None:
            logging.debug(f"Non-compliant due to one rule being None")
            return False
        
        # Compare public IPs
        if 'publicIp' not in golden_rule or 'publicIp' not in network_rule:
            logging.debug(f"publicIp key missing in one of the rules")
            return False
            
        if golden_rule['publicIp'] != network_rule['publicIp']:
            logging.debug(f"Non-compliant due to public IP mismatch: Golden: {golden_rule['publicIp']}, Network: {network_rule['publicIp']}")
            return False
        
        # Add other comparison logic for one-to-many NAT rules here
    
    return True  # Compliant
def compare_vlans(golden_config, network_config, subnet_octet=1):
    """Compare VLANs."""
    logging.debug(f"Comparing VLANs: Golden: {golden_config}, Network: {network_config}")
    
    golden_vlans = golden_config.get('vlans', [])
    network_vlans = network_config.get('vlans', [])
        # Handle None values
    if golden_vlans is None:
        golden_vlans = []
    if network_vlans is None:
        network_vlans = []
    # First check if the VLANs count matches
    if len(golden_vlans) != len(network_vlans):
        logging.debug(f"Non-compliant due to VLANs count mismatch: Golden: {len(golden_vlans)}, Network: {len(network_vlans)}")
        return False
    
    # Create dictionaries by VLAN ID for easier comparison
    golden_vlans_dict = {vlan.get('id'): vlan for vlan in golden_vlans}
    network_vlans_dict = {vlan.get('id'): vlan for vlan in network_vlans}
    
    # Check that all VLAN IDs match
    if set(golden_vlans_dict.keys()) != set(network_vlans_dict.keys()):
        logging.debug(f"Non-compliant due to VLAN IDs mismatch: Golden: {set(golden_vlans_dict.keys())}, Network: {set(network_vlans_dict.keys())}")
        return False
    
    # Compare configuration for each VLAN
    for vlan_id, golden_vlan in golden_vlans_dict.items():
        network_vlan = network_vlans_dict[vlan_id]
        
        # Compare name
        if golden_vlan.get('name') != network_vlan.get('name'):
            logging.debug(f"Non-compliant due to name mismatch on VLAN {vlan_id}: Golden: {golden_vlan.get('name')}, Network: {network_vlan.get('name')}")
            return False
        
        # Compare subnet with octet precision
        if 'subnet' in golden_vlan and 'subnet' in network_vlan:
            golden_subnet = golden_vlan.get('subnet', '').split('/')[0].split('.')
            network_subnet = network_vlan.get('subnet', '').split('/')[0].split('.')
            
            if golden_subnet[:subnet_octet] != network_subnet[:subnet_octet]:
                logging.debug(f"Non-compliant due to subnet mismatch on VLAN {vlan_id}: Golden: {golden_vlan.get('subnet')}, Network: {network_vlan.get('subnet')}")
                return False
        
        # Compare other fields
        for field in ['dhcpHandling', 'dhcpLeaseTime', 'dhcpBootOptionsEnabled', 'dnsNameservers', 'dhcpOptions', 'mandatoryDhcp', 'ipv6']:
            if golden_vlan.get(field) != network_vlan.get(field):
                logging.debug(f"Non-compliant due to {field} mismatch on VLAN {vlan_id}: Golden: {golden_vlan.get(field)}, Network: {network_vlan.get(field)}")
                return False
    
    return True


def compare_third_party_vpn_peers(golden_peers, network_peers, golden_network_tags, network_tags):
    logging.debug(f"Comparing Third-Party VPN Peers: Golden: {golden_peers}, Network: {network_peers}")

    for golden_peer, network_peer in zip(golden_peers, network_peers):
        golden_peer_tags = golden_peer['networkTags']
        network_peer_tags = network_peer['networkTags']

        # Check if the 'all' tag is in the golden peer tags
        if 'all' in golden_peer_tags:
            logging.debug(f"Golden peer {golden_peer['name']} network tag is set to 'all'")
            continue  # Compliant, All tag is set

        # Check if the 'none' tag is in the golden peer tags
        if 'none' in golden_peer_tags:
            logging.debug(f"Golden peer {golden_peer['name']} network tag is set to 'none'")
            continue  # Compliant, None tag is set

        # Check if any of the golden network tags are in the golden peer tags
        if not any(tag in golden_peer_tags for tag in golden_network_tags):
            logging.debug(f"None of the golden network tags {golden_network_tags} found in golden peer {golden_peer['name']}")
            return False

        # Check if the 'all' tag is in the network peer tags
        if 'all' in network_peer_tags:
            logging.debug(f"Network peer {network_peer['name']} tag is set to 'all'")
            continue  # Compliant, All tag is set

        # Check if the 'none' tag is in the network peer tags
        if 'none' in network_peer_tags:
            logging.debug(f"Network peer {network_peer['name']} tag is set to 'none'")
            continue  # Compliant, None tag is set

        # Check if any of the network tags are in the network peer tags
        if not any(tag in network_peer_tags for tag in network_tags):
            logging.debug(f"None of the network tags {network_tags} found in network peer {network_peer['name']}")
            return False

    return True  # Compliant
def compare_appliance_ports(golden_config, network_config):
    """Compare appliance ports configuration."""
    logging.debug(f"Comparing Appliance Ports: Golden: {golden_config}, Network: {network_config}")
    
    golden_ports = golden_config.get('applianceports', [])
    network_ports = network_config.get('applianceports', [])
    
    # First check if the ports count matches
    if len(golden_ports) != len(network_ports):
        logging.debug(f"Non-compliant due to ports count mismatch: Golden: {len(golden_ports)}, Network: {len(network_ports)}")
        return False
    
    # Create dictionaries by port number for easier comparison
    golden_ports_dict = {port.get('number'): port for port in golden_ports}
    network_ports_dict = {port.get('number'): port for port in network_ports}
    
    # Check that all port numbers match
    if set(golden_ports_dict.keys()) != set(network_ports_dict.keys()):
        logging.debug(f"Non-compliant due to port numbers mismatch: Golden: {set(golden_ports_dict.keys())}, Network: {set(network_ports_dict.keys())}")
        return False
    
    # Compare configuration for each port
    for port_number, golden_port in golden_ports_dict.items():
        network_port = network_ports_dict[port_number]
        
        for field in ['type', 'vlan', 'dropUntaggedTraffic', 'enabled', 'accessPolicy']:
            if golden_port.get(field) != network_port.get(field):
                logging.debug(f"Non-compliant due to {field} mismatch on port {port_number}: Golden: {golden_port.get(field)}, Network: {network_port.get(field)}")
                return False
    
    return True

def compare_appliance_settings(golden_config, network_config):
    # Get settings safely
    golden_settings = golden_config.get('settings', {}) or {}
    network_settings = network_config.get('settings', {}) or {}
    
    # If either is None, skip comparison
    if golden_settings is None or network_settings is None:
        return True
    
    # Compare fields that exist in both
    for field in ['vlan', 'uplinkClientSampling', 'macBlocklist']:
        if field in golden_settings and field in network_settings:
            if golden_settings.get(field) != network_settings.get(field):
                return False
    
    return True
def compare_security_intrusion(golden_config, network_config):
    """Compare security intrusion settings."""
    logging.debug(f"Comparing Security Intrusion: Golden: {golden_config}, Network: {network_config}")
    
    golden_intrusion = golden_config.get('securityintrusion', {})
    network_intrusion = network_config.get('securityintrusion', {})
    
    # Check if network_intrusion is None (indicating API error/unsupported feature)
    if network_intrusion is None:
        reason = "Intrusion detection is not supported by this network"
        logging.debug(f"Non-compliant: {reason}")
        return False, reason
    
    # Compare mode and IPS mode
    for field in ['mode', 'idsRulesets', 'protectedNetworks']:
        if golden_intrusion.get(field) != network_intrusion.get(field):
            reason = f"{field} mismatch: Golden: {golden_intrusion.get(field)}, Network: {network_intrusion.get(field)}"
            logging.debug(f"Non-compliant due to {reason}")
            return False, reason
    
    return True, "Compliant"
def compare_warm_spare(golden_config, network_config):
    """Compare warm spare settings."""
    logging.debug(f"Comparing Warm Spare: Golden: {golden_config}, Network: {network_config}")
    
    golden_spare = golden_config.get('warmspare', {})
    network_spare = network_config.get('warmspare', {})
    
    # Compare enabled status
    if golden_spare.get('enabled') != network_spare.get('enabled'):
        logging.debug(f"Non-compliant due to enabled status mismatch: Golden: {golden_spare.get('enabled')}, Network: {network_spare.get('enabled')}")
        return False
    
    # If enabled, compare uplink mode
    if golden_spare.get('enabled'):
        if golden_spare.get('uplinkMode') != network_spare.get('uplinkMode'):
            logging.debug(f"Non-compliant due to uplink mode mismatch: Golden: {golden_spare.get('uplinkMode')}, Network: {network_spare.get('uplinkMode')}")
            return False
    
    return True
def compare_site_to_site_vpn(golden_config, network_config):
    """Compare site-to-site VPN settings."""
    logging.debug(f"Comparing Site-to-Site VPN: Golden: {golden_config}, Network: {network_config}")
    
    golden_vpn = golden_config.get('vpnsitetosite', {})
    network_vpn = network_config.get('vpnsitetosite', {})
    
    # Compare mode
    if golden_vpn.get('mode') != network_vpn.get('mode'):
        logging.debug(f"Non-compliant due to mode mismatch: Golden: {golden_vpn.get('mode')}, Network: {network_vpn.get('mode')}")
        return False
    
    # Compare hub configurations
    golden_hubs = golden_vpn.get('hubs', [])
    network_hubs = network_vpn.get('hubs', [])
    
    if len(golden_hubs) != len(network_hubs):
        logging.debug(f"Non-compliant due to hubs count mismatch: Golden: {len(golden_hubs)}, Network: {len(network_hubs)}")
        return False
    
    # Sort hubs by hub ID for consistent comparison
    golden_hubs = sorted(golden_hubs, key=lambda x: x.get('hubId', ''))
    network_hubs = sorted(network_hubs, key=lambda x: x.get('hubId', ''))
    
    for golden_hub, network_hub in zip(golden_hubs, network_hubs):
        if golden_hub.get('hubId') != network_hub.get('hubId'):
            logging.debug(f"Non-compliant due to hubId mismatch: Golden: {golden_hub.get('hubId')}, Network: {network_hub.get('hubId')}")
            return False
        
        if golden_hub.get('useDefaultRoute') != network_hub.get('useDefaultRoute'):
            logging.debug(f"Non-compliant due to useDefaultRoute mismatch: Golden: {golden_hub.get('useDefaultRoute')}, Network: {network_hub.get('useDefaultRoute')}")
            return False
    
    # Skip comparing subnets which may differ between networks
    return True
def compare_security_malware(golden_config, network_config):
    # Handle string error responses
    if isinstance(golden_config.get('securitymalware'), str) or isinstance(network_config.get('securitymalware'), str):
        return True  # Skip comparison if data collection failed
        
    golden_malware = golden_config.get('securitymalware', {}) or {}
    network_malware = network_config.get('securitymalware', {}) or {}
    
    # Compare mode and allowed URLs
    for field in ['mode', 'allowedUrls', 'allowedFiles']:
        golden_value = golden_malware.get(field, [])
        network_value = network_malware.get(field, [])
        
        if isinstance(golden_value, list) and isinstance(network_value, list):
            if set(golden_value) != set(network_value):
                logging.debug(f"Non-compliant due to {field} mismatch: Golden: {golden_value}, Network: {network_value}")
                return False
        else:
            if golden_value != network_value:
                logging.debug(f"Non-compliant due to {field} mismatch: Golden: {golden_value}, Network: {network_value}")
                return False
    
    return True

def compare_static_routes(golden_config, network_config):
    """Compare static routes."""
    logging.debug(f"Comparing Static Routes: Golden: {golden_config}, Network: {network_config}")
    
    golden_routes = golden_config.get('staticroutes', [])
    network_routes = network_config.get('staticroutes', [])
    
        # Handle None values
    if golden_routes is None:
        golden_routes = []
    if network_routes is None:
        network_routes = []
    # First check if the routes count matches
    if len(golden_routes) != len(network_routes):
        logging.debug(f"Non-compliant due to routes count mismatch: Golden: {len(golden_routes)}, Network: {len(network_routes)}")
        return False
    
    # Sort routes by name for consistent comparison
    golden_routes = sorted(golden_routes, key=lambda x: x.get('name', ''))
    network_routes = sorted(network_routes, key=lambda x: x.get('name', ''))
    
    # Compare each route
    for golden_route, network_route in zip(golden_routes, network_routes):
        for field in ['name', 'subnet', 'gatewayIp', 'enabled']:
            if golden_route.get(field) != network_route.get(field):
                logging.debug(f"Non-compliant due to {field} mismatch: Golden: {golden_route.get(field)}, Network: {network_route.get(field)}")
                return False
    
    return True

def compare_l3_firewall_rules(golden_config, network_config, source_octet=1, dest_octet=1):
    """Compare L3 firewall rules."""
    logging.debug(f"Comparing L3 Firewall Rules: Golden: {golden_config}, Network: {network_config}")
    
    golden_rules = golden_config.get('firewalll3firewallrules', {}).get('rules', [])
    network_rules = network_config.get('firewalll3firewallrules', {}).get('rules', [])
    
    # First check if the rule count matches
    if len(golden_rules) != len(network_rules):
        logging.debug(f"Non-compliant due to rule count mismatch: Golden: {len(golden_rules)}, Network: {len(network_rules)}")
        return False
    
    # Compare each rule
    for golden_rule, network_rule in zip(golden_rules, network_rules):
        # Compare source CIDR with octet precision
        golden_src_ip = golden_rule.get('srcCidr', 'Any')
        network_src_ip = network_rule.get('srcCidr', 'Any')
        
        if golden_src_ip != 'Any' and network_src_ip != 'Any':
            golden_src_octets = golden_src_ip.split('/')[0].split('.')[:source_octet]
            network_src_octets = network_src_ip.split('/')[0].split('.')[:source_octet]
            
            if golden_src_octets != network_src_octets:
                logging.debug(f"Non-compliant due to source IP mismatch: Golden: {golden_src_ip}, Network: {network_src_ip}")
                return False
        elif golden_src_ip != network_src_ip:
            logging.debug(f"Non-compliant due to source IP type mismatch: Golden: {golden_src_ip}, Network: {network_src_ip}")
            return False
        
        # Compare destination CIDR with octet precision
        golden_dest_ip = golden_rule.get('destCidr', 'Any')
        network_dest_ip = network_rule.get('destCidr', 'Any')
        
        if golden_dest_ip != 'Any' and network_dest_ip != 'Any':
            golden_dest_octets = golden_dest_ip.split('/')[0].split('.')[:dest_octet]
            network_dest_octets = network_dest_ip.split('/')[0].split('.')[:dest_octet]
            
            if golden_dest_octets != network_dest_octets:
                logging.debug(f"Non-compliant due to destination IP mismatch: Golden: {golden_dest_ip}, Network: {network_dest_ip}")
                return False
        elif golden_dest_ip != network_dest_ip:
            logging.debug(f"Non-compliant due to destination IP type mismatch: Golden: {golden_dest_ip}, Network: {network_dest_ip}")
            return False
        
        # Compare other fields
        for field in ['policy', 'protocol', 'srcPort', 'destPort', 'syslogEnabled', 'comment']:
            if golden_rule.get(field) != network_rule.get(field):
                logging.debug(f"Non-compliant due to {field} mismatch: Golden: {golden_rule.get(field)}, Network: {network_rule.get(field)}")
                return False
    
    return True
def compare_l7_firewall_rules(golden_config, network_config):
    """Compare L7 firewall rules."""
    logging.debug(f"Comparing L7 Firewall Rules: Golden: {golden_config}, Network: {network_config}")
    
    golden_rules = golden_config.get('firewalll7firewallrules', {}).get('rules', [])
    network_rules = network_config.get('firewalll7firewallrules', {}).get('rules', [])
    
    # First check if the rule count matches
    if len(golden_rules) != len(network_rules):
        logging.debug(f"Non-compliant due to rule count mismatch: Golden: {len(golden_rules)}, Network: {len(network_rules)}")
        return False
    
    # Compare each rule
    for golden_rule, network_rule in zip(golden_rules, network_rules):
        # Compare policy
        if golden_rule.get('policy') != network_rule.get('policy'):
            logging.debug(f"Non-compliant due to policy mismatch: Golden: {golden_rule.get('policy')}, Network: {network_rule.get('policy')}")
            return False
        
        # Compare type
        if golden_rule.get('type') != network_rule.get('type'):
            logging.debug(f"Non-compliant due to type mismatch: Golden: {golden_rule.get('type')}, Network: {network_rule.get('type')}")
            return False
        
        # Compare value
        if golden_rule.get('value') != network_rule.get('value'):
            logging.debug(f"Non-compliant due to value mismatch: Golden: {golden_rule.get('value')}, Network: {network_rule.get('value')}")
            return False
    
    return True


def compare_connectivity_monitoring(golden_config, network_config):

    logging.debug(f"Comparing Connectivity Monitoring: Golden: {golden_config}, Network: {network_config}")
    
    golden_destinations = golden_config.get('connectivitymonitoringdestinations', {}).get('destinations', [])
    network_destinations = network_config.get('connectivitymonitoringdestinations', {}).get('destinations', [])
    
    # Check if the destinations count matches
    if len(golden_destinations) != len(network_destinations):
        logging.debug(f"Non-compliant due to destinations count mismatch: Golden: {len(golden_destinations)}, Network: {len(network_destinations)}")
        return False
    
    # Sort destinations by IP for consistent comparison
    golden_destinations = sorted(golden_destinations, key=lambda x: x.get('ip', ''))
    network_destinations = sorted(network_destinations, key=lambda x: x.get('ip', ''))
    
    # Compare each destination
    for golden_dest, network_dest in zip(golden_destinations, network_destinations):
        if golden_dest.get('ip') != network_dest.get('ip'):
            logging.debug(f"Non-compliant due to destination IP mismatch: Golden: {golden_dest.get('ip')}, Network: {network_dest.get('ip')}")
            return False
        
        if golden_dest.get('description') != network_dest.get('description'):
            logging.debug(f"Non-compliant due to destination description mismatch: Golden: {golden_dest.get('description')}, Network: {network_dest.get('description')}")
            return False
    
    return True
def compare_switch_dhcp_server_policy(golden_config, network_config):
    """Compare switch DHCP server policy."""
    logging.debug(f"Comparing Switch DHCP Server Policy: Golden: {golden_config}, Network: {network_config}")
    
    golden_policy = golden_config.get('dhcpserverpolicy', {})
    network_policy = network_config.get('dhcpserverpolicy', {})
    
    # Compare default policy
    if golden_policy.get('defaultPolicy') != network_policy.get('defaultPolicy'):
        logging.debug(f"Non-compliant due to default policy mismatch: Golden: {golden_policy.get('defaultPolicy')}, Network: {network_policy.get('defaultPolicy')}")
        return False
    
    # Compare allowed servers
    golden_allowed = set(golden_policy.get('allowedServers', []))
    network_allowed = set(network_policy.get('allowedServers', []))
    if golden_allowed != network_allowed:
        logging.debug(f"Non-compliant due to allowed servers mismatch: Golden: {golden_allowed}, Network: {network_allowed}")
        return False

def compare_switch_dscp_to_cos(golden_config, network_config):
    """Compare DSCP to CoS mappings."""
    logging.debug(f"Comparing DSCP to CoS Mappings: Golden: {golden_config}, Network: {network_config}")
    
    golden_mappings = golden_config.get('dscptocosmappings', {}).get('mappings', [])
    network_mappings = network_config.get('dscptocosmappings', {}).get('mappings', [])
    
    # Check if the mappings count matches
    if len(golden_mappings) != len(network_mappings):
        logging.debug(f"Non-compliant due to mappings count mismatch: Golden: {len(golden_mappings)}, Network: {len(network_mappings)}")
        return False
    
    # Sort mappings by DSCP value for consistent comparison
    golden_mappings = sorted(golden_mappings, key=lambda x: x.get('dscp', 0))
    network_mappings = sorted(network_mappings, key=lambda x: x.get('dscp', 0))
    
    # Compare each mapping
    for golden_mapping, network_mapping in zip(golden_mappings, network_mappings):
        for field in ['dscp', 'cos', 'title']:
            if golden_mapping.get(field) != network_mapping.get(field):
                logging.debug(f"Non-compliant due to {field} mismatch: Golden: {golden_mapping.get(field)}, Network: {network_mapping.get(field)}")
                return False
    
    return True
def compare_switch_mtu(golden_config, network_config):
    """Compare switch MTU settings."""
    logging.debug(f"Comparing Switch MTU: Golden: {golden_config}, Network: {network_config}")
    
    golden_mtu = golden_config.get('mtu', {})
    network_mtu = network_config.get('mtu', {})
    
    # Compare default MTU size
    if golden_mtu.get('defaultMtuSize') != network_mtu.get('defaultMtuSize'):
        logging.debug(f"Non-compliant due to default MTU size mismatch: Golden: {golden_mtu.get('defaultMtuSize')}, Network: {network_mtu.get('defaultMtuSize')}")
        return False
    
    # Compare MTU overrides
    golden_overrides = golden_mtu.get('overrides', [])
    network_overrides = network_mtu.get('overrides', [])
    
    if len(golden_overrides) != len(network_overrides):
        logging.debug(f"Non-compliant due to MTU overrides count mismatch: Golden: {len(golden_overrides)}, Network: {len(network_overrides)}")
        return False
    
    # Sort overrides for consistent comparison if they exist
    if golden_overrides and network_overrides:
        golden_overrides = sorted(golden_overrides, key=lambda x: str(x.get('switchProfiles', [])))
        network_overrides = sorted(network_overrides, key=lambda x: str(x.get('switchProfiles', [])))
        
        # Compare each override
        for golden_override, network_override in zip(golden_overrides, network_overrides):
            if golden_override.get('mtuSize') != network_override.get('mtuSize'):
                logging.debug(f"Non-compliant due to MTU size mismatch in override: Golden: {golden_override.get('mtuSize')}, Network: {network_override.get('mtuSize')}")
                return False
    
    return True
def compare_switch_port_schedules(golden_config, network_config):
    """Compare switch port schedules."""
    logging.debug(f"Comparing Switch Port Schedules: Golden: {golden_config}, Network: {network_config}")
    
    golden_schedules = golden_config.get('portschedules')
    network_schedules = network_config.get('portschedules')
    
    # If both are None or empty lists, consider it compliant
    if (golden_schedules is None or golden_schedules == []) and \
       (network_schedules is None or network_schedules == []):
        logging.debug("No port schedules configured for both golden and network. Compliant.")
        return True
    
    # At this point, if one is None/empty and the other isn't, it's non-compliant
    if (golden_schedules is None or golden_schedules == []) or \
       (network_schedules is None or network_schedules == []):
        logging.debug("Port schedules mismatch: One network has schedules, the other doesn't.")
        return False
    
    # Create dictionaries by schedule name for easier comparison
    golden_schedules_dict = {schedule.get('name'): schedule for schedule in golden_schedules}
    network_schedules_dict = {schedule.get('name'): schedule for schedule in network_schedules}
    
    # Check that all schedule names match
    if set(golden_schedules_dict.keys()) != set(network_schedules_dict.keys()):
        logging.debug(f"Non-compliant due to schedule names mismatch: Golden: {set(golden_schedules_dict.keys())}, Network: {set(network_schedules_dict.keys())}")
        return False
    
    # Compare configuration for each schedule
    for schedule_name, golden_schedule in golden_schedules_dict.items():
        network_schedule = network_schedules_dict[schedule_name]
        
        for field in ['portSchedule']:
            if golden_schedule.get(field) != network_schedule.get(field):
                logging.debug(f"Non-compliant due to {field} mismatch for schedule {schedule_name}: Golden: {golden_schedule.get(field)}, Network: {network_schedule.get(field)}")
                return False
    
    return True
def compare_switch_qos_rules(golden_config, network_config):
    """Compare Switch QoS rules."""
    logging.debug(f"Comparing Switch QoS: Golden: {golden_config}, Network: {network_config}")
    
    golden_rules = golden_config.get('qosrules', [])
    network_rules = network_config.get('qosrules', [])
    
    # Handle None values
    if golden_rules is None:
        golden_rules = []
    if network_rules is None:
        network_rules = []
    
    # Check if the rules count matches
    if len(golden_rules) != len(network_rules):
        logging.debug(f"Non-compliant due to QoS rules count mismatch: Golden: {len(golden_rules)}, Network: {len(network_rules)}")
        return False
    
    # Skip comparing rule IDs (they will be different)
    # Instead compare the configuration values
    if golden_rules and network_rules:
        for golden_rule, network_rule in zip(golden_rules, network_rules):
            # Compare VLAN
            if golden_rule.get('vlan') != network_rule.get('vlan'):
                logging.debug(f"Non-compliant due to VLAN mismatch: Golden: {golden_rule.get('vlan')}, Network: {network_rule.get('vlan')}")
                return False
            
            # Compare protocol
            if golden_rule.get('protocol') != network_rule.get('protocol'):
                logging.debug(f"Non-compliant due to protocol mismatch: Golden: {golden_rule.get('protocol')}, Network: {network_rule.get('protocol')}")
                return False
            
            # Compare port ranges
            for field in ['srcPortRange', 'dstPortRange']:
                if golden_rule.get(field) != network_rule.get(field):
                    logging.debug(f"Non-compliant due to {field} mismatch: Golden: {golden_rule.get(field)}, Network: {network_rule.get(field)}")
                    return False
            
            # Compare DSCP
            if golden_rule.get('dscp') != network_rule.get('dscp'):
                logging.debug(f"Non-compliant due to DSCP mismatch: Golden: {golden_rule.get('dscp')}, Network: {network_rule.get('dscp')}")
                return False
    
    return True
def compare_switch_settings(golden_config, network_config):
    """Compare switch settings."""
    logging.debug(f"Comparing Switch Settings: Golden: {golden_config}, Network: {network_config}")
    
    golden_settings = golden_config.get('settings', {})
    network_settings = network_config.get('settings', {})
    
    # Compare various switch settings
    for field in ['vlan', 'useCombinedPower', 'powerExceptions', 'uplinkClientSampling']:
        if golden_settings.get(field) != network_settings.get(field):
            logging.debug(f"Non-compliant due to {field} mismatch: Golden: {golden_settings.get(field)}, Network: {network_settings.get(field)}")
            return False
    
    return True
def compare_switch_storm_control(golden_config, network_config):
    """Compare switch storm control settings."""
    logging.debug(f"Comparing Switch Storm Control: Golden: {golden_config}, Network: {network_config}")
    
    golden_storm = golden_config.get('stormcontrol')
    network_storm = network_config.get('stormcontrol')
    
    # If both are None, consider it compliant
    if golden_storm is None and network_storm is None:
        return True
    
    # If only one is None, they don't match
    if golden_storm is None or network_storm is None:
        logging.debug(f"Non-compliant: Storm control configuration mismatch - Golden: {golden_storm}, Network: {network_storm}")
        return False
    
    # Now safely compare fields since neither is None
    for field in ['broadcastThreshold', 'multicastThreshold', 'unknownUnicastThreshold']:
        if golden_storm.get(field) != network_storm.get(field):
            logging.debug(f"Non-compliant due to {field} mismatch: Golden: {golden_storm.get(field)}, Network: {network_storm.get(field)}")
            return False
    
    # Compare traffic types
    golden_types = set(golden_storm.get('treatTheseTrafficTypesAsOneThreshold', []))
    network_types = set(network_storm.get('treatTheseTrafficTypesAsOneThreshold', []))
    if golden_types != network_types:
        logging.debug(f"Non-compliant due to traffic types mismatch: Golden: {golden_types}, Network: {network_types}")
        return False
    
    return True
def compare_switch_stp(golden_config, network_config):
    """Compare switch STP settings."""
    logging.debug(f"Comparing Switch STP: Golden: {golden_config}, Network: {network_config}")
    
    golden_stp = golden_config.get('stp', {})
    network_stp = network_config.get('stp', {})
    
    # Compare RSTP enabled
    if golden_stp.get('rstpEnabled') != network_stp.get('rstpEnabled'):
        logging.debug(f"Non-compliant due to RSTP enabled mismatch: Golden: {golden_stp.get('rstpEnabled')}, Network: {network_stp.get('rstpEnabled')}")
        return False
    
    # Compare STP bridge priority - ignore switch IDs as they will be different
    golden_priorities = golden_stp.get('stpBridgePriority', [])
    network_priorities = network_stp.get('stpBridgePriority', [])
    
    if len(golden_priorities) != len(network_priorities):
        logging.debug(f"Non-compliant due to STP bridge priority count mismatch: Golden: {len(golden_priorities)}, Network: {len(network_priorities)}")
        return False
    
    # Check that all priorities match
    golden_priority_values = [priority.get('stpPriority') for priority in golden_priorities]
    network_priority_values = [priority.get('stpPriority') for priority in network_priorities]
    
    if set(golden_priority_values) != set(network_priority_values):
        logging.debug(f"Non-compliant due to STP priority values mismatch: Golden: {golden_priority_values}, Network: {network_priority_values}")
        return False
    
    return True
def compare_switch_acls(golden_config, network_config):
    """Compare switch ACL configurations."""
    logging.debug(f"Comparing Switch ACLs: Golden: {golden_config}, Network: {network_config}")
    
    golden_acls = golden_config.get('accesscontrollists', {})
    network_acls = network_config.get('accesscontrollists', {})
    
    # Compare rules
    golden_rules = golden_acls.get('rules', [])
    network_rules = network_acls.get('rules', [])
    
    if len(golden_rules) != len(network_rules):
        logging.debug(f"Non-compliant due to ACL rules count mismatch: Golden: {len(golden_rules)}, Network: {len(network_rules)}")
        return False
    
    # Compare each rule in order (order matters for ACLs)
    for i, (golden_rule, network_rule) in enumerate(zip(golden_rules, network_rules)):
        for field in ['policy', 'ipVersion', 'protocol', 'srcCidr', 'dstCidr', 'srcPort', 'dstPort', 'vlan', 'comment']:
            if golden_rule.get(field) != network_rule.get(field):
                logging.debug(f"Non-compliant due to {field} mismatch in rule {i}: Golden: {golden_rule.get(field)}, Network: {network_rule.get(field)}")
                return False
    
    return True

# MR Wireless comparison functions
def compare_wireless_ssids(golden_config, network_config):
    """Compare wireless SSID configurations."""
    logging.debug(f"Comparing Wireless SSIDs: Golden: {golden_config}, Network: {network_config}")
    
    # Get the SSIDs from the configuration dictionaries
    golden_ssids = golden_config.get('wirelessssids', [])
    network_ssids = network_config.get('wirelessssids', [])
    
    # Handle None values
    if golden_ssids is None:
        golden_ssids = []
    if network_ssids is None:
        network_ssids = []
    
    # Create dictionaries indexed by SSID number for easier comparison
    golden_ssid_map = {ssid.get('number'): ssid for ssid in golden_ssids}
    network_ssid_map = {ssid.get('number'): ssid for ssid in network_ssids}
    
    # Debug output to see what we're comparing
    logging.debug(f"Golden SSIDs map keys: {list(golden_ssid_map.keys())}")
    logging.debug(f"Network SSIDs map keys: {list(network_ssid_map.keys())}")
    
    # Check each enabled SSID in the golden config
    for ssid_num, golden_ssid in golden_ssid_map.items():
        # Only check enabled SSIDs in the golden config
        if golden_ssid.get('enabled', False):
            logging.debug(f"Checking enabled SSID {ssid_num} from golden config: {golden_ssid.get('name')}")
            
            # Ensure this SSID exists in the network config
            if ssid_num not in network_ssid_map:
                logging.debug(f"Non-compliant: SSID {ssid_num} not found in network config")
                return False
            
            network_ssid = network_ssid_map[ssid_num]
            
            # Check if the SSID is enabled in the network config
            if not network_ssid.get('enabled', False):
                logging.debug(f"Non-compliant: SSID {ssid_num} is not enabled in network config")
                return False
            
            # Compare name (explicitly as strings to catch potential type issues)
            golden_name = str(golden_ssid.get('name', ''))
            network_name = str(network_ssid.get('name', ''))
            if golden_name != network_name:
                logging.debug(f"Non-compliant: SSID {ssid_num} name mismatch - Golden: '{golden_name}', Network: '{network_name}'")
                return False
            
            # Compare authentication mode (explicitly as strings)
            golden_auth = str(golden_ssid.get('authMode', ''))
            network_auth = str(network_ssid.get('authMode', ''))
            if golden_auth != network_auth:
                logging.debug(f"Non-compliant: SSID {ssid_num} authMode mismatch - Golden: '{golden_auth}', Network: '{network_auth}'")
                return False
            
            # Compare other important settings
            for field in ['encryptionMode', 'minBitrate', 'bandSelection', 'ipAssignmentMode']:
                if field in golden_ssid or field in network_ssid:
                    golden_value = golden_ssid.get(field)
                    network_value = network_ssid.get(field)
                    if golden_value != network_value:
                        logging.debug(f"Non-compliant: SSID {ssid_num} {field} mismatch - Golden: '{golden_value}', Network: '{network_value}'")
                        return False
    
    # All checks passed
    logging.debug("All SSID checks passed - compliant")
    return True


def compare_wireless_rf_profiles(golden_config, network_config):
    logging.debug(f"Comparing Wireless RF Profiles: Golden: {golden_config}, Network: {network_config}")
    if isinstance(golden_config.get('wirelessrfprofiles'), str) or isinstance(network_config.get('wirelessrfprofiles'), str):
        # Skip comparison if Data Collection Failed
        return True
    golden_profiles = golden_config.get('wirelessrfprofiles', [])
    network_profiles = network_config.get('wirelessrfprofiles', [])
    
    # Handle None values
    if golden_profiles is None:
        golden_profiles = []
    if network_profiles is None:
        network_profiles = []
    
    # Create dictionaries indexed by profile name for easier comparison
    golden_profiles_dict = {profile.get('name'): profile for profile in golden_profiles}
    network_profiles_dict = {profile.get('name'): profile for profile in network_profiles}
    
    # Check that all profile names match
    if set(golden_profiles_dict.keys()) != set(network_profiles_dict.keys()):
        logging.debug(f"Non-compliant due to RF profile names mismatch: Golden: {set(golden_profiles_dict.keys())}, Network: {set(network_profiles_dict.keys())}")
        return False
    
    # Compare each profile
    for profile_name, golden_profile in golden_profiles_dict.items():
        network_profile = network_profiles_dict[profile_name]
        
        # Compare basic settings
        for field in ['clientBalancingEnabled', 'minBitrateType', 'bandSelectionType']:
            if golden_profile.get(field) != network_profile.get(field):
                logging.debug(f"Non-compliant due to {field} mismatch for RF profile {profile_name}")
                return False
        
        # Compare band-specific settings
        for band in ['fiveGhzSettings', 'twoFourGhzSettings']:
            if band in golden_profile and band in network_profile:
                golden_band = golden_profile[band]
                network_band = network_profile[band]
                
                for band_field in ['minBitrate', 'axEnabled']:
                    if band_field in golden_band and band_field in network_band:
                        if golden_band[band_field] != network_band[band_field]:
                            logging.debug(f"Non-compliant due to {band}.{band_field} mismatch for RF profile {profile_name}")
                            return False
    
    return True

def compare_wireless_settings(golden_config, network_config):
    """Compare wireless network settings."""
    logging.debug(f"Comparing Wireless Settings: Golden: {golden_config}, Network: {network_config}")
    
    golden_settings = golden_config.get('wirelesssettings')
    network_settings = network_config.get('wirelesssettings')
    
    # If either is None, handle as template unsupported
    if golden_settings is None or network_settings is None:
        return True
    
    # Compare key settings
    for field in ['meshingEnabled', 'ipv6BridgeEnabled', 'locationAnalyticsEnabled', 'upgradeStrategy', 'ledLightsOn']:
        if field in golden_settings and field in network_settings:
            if golden_settings.get(field) != network_settings.get(field):
                logging.debug(f"Non-compliant due to {field} mismatch in wireless settings")
                return False
    
    return True

def compare_wireless_alternate_management_interface(golden_config, network_config):
    """Compare wireless alternate management interface settings."""
    logging.debug(f"Comparing Wireless Alternate Management Interface: Golden: {golden_config}, Network: {network_config}")
    
    golden_ami = golden_config.get('wirelessalternatemanagementinterface', {})
    network_ami = network_config.get('wirelessalternatemanagementinterface', {})
    
    # Compare enabled status
    if golden_ami.get('enabled') != network_ami.get('enabled'):
        logging.debug(f"Non-compliant due to enabled status mismatch for AMI")
        return False
    
    return True

def compare_wireless_bluetooth_settings(golden_config, network_config):
    """Compare wireless Bluetooth settings."""
    logging.debug(f"Comparing Wireless Bluetooth Settings: Golden: {golden_config}, Network: {network_config}")
    
    golden_bluetooth = golden_config.get('wirelessbluetoothsettings', {})
    network_bluetooth = network_config.get('wirelessbluetoothsettings', {})
    
    # Compare settings
    for field in ['scanningEnabled', 'advertisingEnabled']:
        if golden_bluetooth.get(field) != network_bluetooth.get(field):
            logging.debug(f"Non-compliant due to {field} mismatch in Bluetooth settings")
            return False
    
    return True

def compare_wireless_ssid_l3_firewall_rules(golden_config, network_config):
    """Compare wireless SSID L3 firewall rules."""
    logging.debug(f"Comparing Wireless SSID L3 Firewall Rules: Golden: {golden_config}, Network: {network_config}")
    
    golden_rules = golden_config.get('firewalll3firewallrules', {})
    network_rules = network_config.get('firewalll3firewallrules', {})
    
    # Skip detailed comparison if both are "Data Collection Failed"
    if golden_rules == "Data Collection Failed" and network_rules == "Data Collection Failed":
        return True
    
    # Check basic rules
    if golden_rules and network_rules:
        if golden_rules.get('rules') != network_rules.get('rules'):
            logging.debug("Non-compliant due to L3 firewall rules mismatch")
            return False
    
    return True

def compare_wireless_ssid_l7_firewall_rules(golden_config, network_config):
    """Compare wireless SSID L7 firewall rules."""
    logging.debug(f"Comparing Wireless SSID L7 Firewall Rules: Golden: {golden_config}, Network: {network_config}")
    
    golden_rules = golden_config.get('firewalll7firewallrules', {})
    network_rules = network_config.get('firewalll7firewallrules', {})
    
    # Skip detailed comparison if both are "Data Collection Failed"
    if golden_rules == "Data Collection Failed" and network_rules == "Data Collection Failed":
        return True
    
    # Check basic rules
    if golden_rules and network_rules:
        if golden_rules.get('rules') != network_rules.get('rules'):
            logging.debug("Non-compliant due to L7 firewall rules mismatch")
            return False
    
    return True

def compare_wireless_ssid_traffic_shaping_rules(golden_config, network_config):
    """Compare wireless SSID traffic shaping rules."""
    logging.debug(f"Comparing Wireless SSID Traffic Shaping Rules: Golden: {golden_config}, Network: {network_config}")
    
    golden_rules = golden_config.get('trafficshapingrules', {})
    network_rules = network_config.get('trafficshapingrules', {})
    
    # Skip detailed comparison if both are "Data Collection Failed"
    if golden_rules == "Data Collection Failed" and network_rules == "Data Collection Failed":
        return True
    
    # Compare bandwidth limits
    if golden_rules and network_rules:
        golden_bw = golden_rules.get('bandwidthLimits', {})
        network_bw = network_rules.get('bandwidthLimits', {})
        
        if golden_bw != network_bw:
            logging.debug("Non-compliant due to bandwidth limits mismatch")
            return False
        
        # Compare rules
        if golden_rules.get('rules') != network_rules.get('rules'):
            logging.debug("Non-compliant due to traffic shaping rules mismatch")
            return False
    
    return True

def compare_wireless_ssid_identity_psks(golden_config, network_config):
    """Compare wireless SSID identity PSKs."""
    logging.debug(f"Comparing Wireless SSID Identity PSKs: Golden: {golden_config}, Network: {network_config}")
    
    golden_psks = golden_config.get('identitypsks', [])
    network_psks = network_config.get('identitypsks', [])
    
    # Skip detailed comparison if both are "Data Collection Failed"
    if golden_psks == "Data Collection Failed" and network_psks == "Data Collection Failed":
        return True
    
    # Simple length check as PSKs may contain sensitive data
    if len(golden_psks) != len(network_psks):
        logging.debug("Non-compliant due to PSK count mismatch")
        return False
    
    return True
def compare_wireless_radio_settings(golden_data, compliance_data):

    results = []
    
    # Extract RF profiles from the golden and compliance data
    golden_profiles = golden_data.get('wirelessrfprofiles', [])
    compliance_profiles = compliance_data.get('wirelessrfprofiles', [])
    
    # Create lookup dictionaries based on profile name for easier comparison
    golden_profiles_dict = {profile.get('name'): profile for profile in golden_profiles}
    compliance_profiles_dict = {profile.get('name'): profile for profile in compliance_profiles}
    
    # Compare each golden profile to see if it exists in compliance network
    for profile_name, golden_profile in golden_profiles_dict.items():
        compliance_profile = compliance_profiles_dict.get(profile_name)
        
        if not compliance_profile:
            # Profile doesn't exist in compliance network
            results.append({
                'setting': f"RF Profile: {profile_name}",
                'golden_value': "Present",
                'compliance_value': "Missing",
                'compliant': False
            })
            continue
        
        # Compare specific settings within the profile
        for key in ['bandSelectionType', 'clientBalancingEnabled', 'minBitrateType']:
            if key in golden_profile:
                golden_value = golden_profile.get(key)
                compliance_value = compliance_profile.get(key)
                
                results.append({
                    'setting': f"RF Profile ({profile_name}): {key}",
                    'golden_value': golden_value,
                    'compliance_value': compliance_value,
                    'compliant': golden_value == compliance_value
                })
        
        # Compare 5GHz and 2.4GHz settings
        for band in ['fiveGhzSettings', 'twoFourGhzSettings']:
            if band in golden_profile:
                for setting in ['axEnabled', 'channelWidth', 'minBitrate']:
                    golden_band_settings = golden_profile.get(band, {})
                    compliance_band_settings = compliance_profile.get(band, {})
                    
                    golden_value = golden_band_settings.get(setting)
                    compliance_value = compliance_band_settings.get(setting)
                    
                    results.append({
                        'setting': f"RF Profile ({profile_name}): {band}.{setting}",
                        'golden_value': golden_value,
                        'compliance_value': compliance_value,
                        'compliant': golden_value == compliance_value
                    })
    
    return results
def compare_wireless_ethernet_ports_profiles(golden_data, network_data, comparison_results):

    category = "Wireless Ethernet Ports Profiles"
    
    # Check if wirelesssettings key exists in both datasets
    if 'wirelesssettings' not in golden_data or 'wirelesssettings' not in network_data:
        comparison_results[category] = {
            "status": "Not Compared",
            "message": "Ethernet port settings data missing from either golden image or checked network"
        }
        return comparison_results
    
    # Extract Ethernet ports settings
    try:
        # Get access to the ethernet settings
        golden_settings = golden_data['wirelesssettings'].get('ethernetPortsProfile', {})
        network_settings = network_data['wirelesssettings'].get('ethernetPortsProfile', {})
        
        # Perform comparison - first check if structures are identical
        if golden_settings == network_settings:
            comparison_results[category] = {
                "status": "Compliant",
                "message": "Ethernet ports profiles match exactly"
            }
        else:
            # If not identical, identify specific differences
            differences = []
            
            # Check profile type if present
            if golden_settings.get('profileType') != network_settings.get('profileType'):
                differences.append(f"Profile type: Golden={golden_settings.get('profileType')}, Network={network_settings.get('profileType')}")
            
            # Check port configurations
            golden_ports = golden_settings.get('ports', {})
            network_ports = network_settings.get('ports', {})
            
            for port_num in set(golden_ports.keys()) | set(network_ports.keys()):
                if port_num not in golden_ports:
                    differences.append(f"Port {port_num} missing in golden image")
                elif port_num not in network_ports:
                    differences.append(f"Port {port_num} missing in network being checked")
                elif golden_ports[port_num] != network_ports[port_num]:
                    golden_port = golden_ports[port_num]
                    network_port = network_ports[port_num]
                    
                    # Check specific port settings
                    if golden_port.get('enabled') != network_port.get('enabled'):
                        differences.append(f"Port {port_num} enabled state: Golden={'enabled' if golden_port.get('enabled') else 'disabled'}, "
                                           f"Network={'enabled' if network_port.get('enabled') else 'disabled'}")
                    
                    if golden_port.get('poeEnabled') != network_port.get('poeEnabled'):
                        differences.append(f"Port {port_num} PoE state: Golden={'enabled' if golden_port.get('poeEnabled') else 'disabled'}, "
                                           f"Network={'enabled' if network_port.get('poeEnabled') else 'disabled'}")
                    
                    if golden_port.get('type') != network_port.get('type'):
                        differences.append(f"Port {port_num} type: Golden={golden_port.get('type')}, Network={network_port.get('type')}")
            
            # Add result to comparison_results
            comparison_results[category] = {
                "status": "Non-Compliant",
                "message": "Ethernet ports profiles do not match",
                "differences": differences
            }
            
    except Exception as e:
        comparison_results[category] = {
            "status": "Error",
            "message": f"Error comparing Ethernet ports profiles: {str(e)}"
        }
    
    return comparison_results
def compare_wireless_features(golden_config, network_config):
    """Generic function to compare any wireless feature that might return string errors"""
    # Check for template-specific string
    if isinstance(golden_config, str) and 'Not supported for templates' in golden_config:
        return True  # Skip comparison for templates as this feature is not supported
        
    # Also check if it's in the nested dictionary structure
    if isinstance(golden_config, dict):
        for key, value in golden_config.items():
            if isinstance(value, str) and 'Not supported for templates' in value:
                return True  # Skip comparison for templates

    # Check for error string responses
    if isinstance(golden_config, str) or isinstance(network_config, str):
        # If golden is 'Data Collection Failed' and network has data, mark as non-compliant
        if golden_config == 'Data Collection Failed' and network_config != 'Data Collection Failed':
            return False
        # If both failed or if network failed but golden succeeded, skip comparison
        return True
    
    # Normal comparison if both are dictionaries
    return deep_compare(golden_config, network_config)

def compare_octets(golden_ip, network_ip, octet):
    golden_octets = golden_ip.split('.')
    network_octets = network_ip.split('.')
    result = golden_octets[:octet] == network_octets[:octet]
    logging.debug(f"Comparing IPs: Golden: {golden_ip}, Network: {network_ip}, Octets: {octet}, Result: {result}")
    logging.debug(f"Golden Octets: {golden_octets[:octet]}, Network Octets: {network_octets[:octet]}")
    return result

def is_api_error_response(data):

    # Check if it's a dictionary with a single key
    if isinstance(data, dict):
        # Check for error message in values
        for key, value in data.items():
            if isinstance(value, str) and ('error' in value.lower() or 'This endpoint only supports' in value.lower()):
                return True, value
            
        # Check for error structure in the dictionary itself
        if 'errors' in data and isinstance(data['errors'], list):
            return True, ', '.join(data['errors'])
    
    return False, None


def get_check_data(golden_data, network_data, check):

    # Extract the key name from the check function name
    key = check.replace('getNetwork', '').replace('getOrganization', '').replace('Appliance', '').replace('Switch', '').lower()
    
    # Create new dictionaries with just the data we need for this check
    golden_check_data = {key: golden_data.get(key, None)}
    network_check_data = {key: network_data.get(key, None)}
    
    logging.debug(f"Golden check data for {check}: {golden_check_data}")
    logging.debug(f"Network check data for {check}: {network_check_data}")
    
    return golden_check_data, network_check_data
def compare_data_with_structure_differences(golden_data, network_data, check_key):
    """Compare data that might have different structures but equivalent content"""
    
    # Get the key values
    golden_value = golden_data.get(check_key)
    network_value = network_data.get(check_key)
    
    # If either is a string or None, handle specially
    if isinstance(golden_value, str) or golden_value is None or isinstance(network_value, str) or network_value is None:
        return golden_value == network_value
    
    # Extract content from network_value if it has numbered keys (like "0")
    if isinstance(network_value, dict) and all(k.isdigit() for k in network_value.keys() if isinstance(k, str)):
        # Use the first item (usually "0") for comparison
        first_key = next(iter(network_value))
        network_value = network_value.get(first_key, {})
    
    # Compare essential fields only
    return compare_essential_fields(golden_value, network_value)


# Switch compliance check functions

    # Compare each rule
    for golden_rule, network_rule in zip(golden_rules, network_rules):
        # Compare source CIDR with octet precision
        golden_src_ip = golden_rule.get('srcCidr', 'Any')
        network_src_ip = network_rule.get('srcCidr', 'Any')
        
        if golden_src_ip != 'Any' and network_src_ip != 'Any':
            golden_src_octets = golden_src_ip.split('/')[0].split('.')[:source_octet]
            network_src_octets = network_src_ip.split('/')[0].split('.')[:source_octet]
            
            if golden_src_octets != network_src_octets:
                logging.debug(f"Non-compliant due to source IP mismatch: Golden: {golden_src_ip}, Network: {network_src_ip}")
                return False
        elif golden_src_ip != network_src_ip:
            logging.debug(f"Non-compliant due to source IP type mismatch: Golden: {golden_src_ip}, Network: {network_src_ip}")
            return False
        
        # Compare destination CIDR with octet precision
        golden_dest_ip = golden_rule.get('destCidr', 'Any')
        network_dest_ip = network_rule.get('destCidr', 'Any')
        
        if golden_dest_ip != 'Any' and network_dest_ip != 'Any':
            golden_dest_octets = golden_dest_ip.split('/')[0].split('.')[:dest_octet]
            network_dest_octets = network_dest_ip.split('/')[0].split('.')[:dest_octet]
            
            if golden_dest_octets != network_dest_octets:
                logging.debug(f"Non-compliant due to destination IP mismatch: Golden: {golden_dest_ip}, Network: {network_dest_ip}")
                return False
        elif golden_dest_ip != network_dest_ip:
            logging.debug(f"Non-compliant due to destination IP type mismatch: Golden: {golden_dest_ip}, Network: {network_dest_ip}")
            return False
        
        # Compare other fields
        for field in ['policy', 'protocol', 'srcPort', 'destPort', 'syslogEnabled']:
            if golden_rule.get(field) != network_rule.get(field):
                logging.debug(f"Non-compliant due to {field} mismatch: Golden: {golden_rule.get(field)}, Network: {network_rule.get(field)}")
                return False
    
    return True

def is_template_unsupported(data, check_key):
    value = data.get(check_key)
    if isinstance(value, str) and ("Not Applicable - Unsupported for templates" in value or "Not supported for templates" in value):
        return True
    
    # Also check if it's in the nested structure
    if isinstance(value, dict):
        for _, nested_value in value.items():
            if isinstance(nested_value, str) and ("Not Applicable - Unsupported for templates" in nested_value or "Not supported for templates" in nested_value):
                return True
    
    return False
def run_compliance_check():
    logging.debug("Running compliance check")
    
    # Load session data
    session_data = load_json('session_data.json')
    logging.debug(f"Loaded session data: {session_data}")
    
    # Extract session data
    orgs = session_data['orgs']
    mx_checks = session_data['mx_checks']
    ms_checks = session_data['ms_checks']
    mr_checks = session_data['mr_checks']
    golden_images = session_data['golden_images']
    compliance_networks = session_data['compliance_networks']
    api_key = session_data['api_key']
    template_ids = session_data.get('template_ids', [])
    
    # Extract octet settings
    l3_firewall_source_octet = int(session_data.get('l3_firewall_source_octet', 4))
    l3_firewall_destination_octet = int(session_data.get('l3_firewall_destination_octet', 4))
    cellular_firewall_source_octet = int(session_data.get('cellular_firewall_source_octet', 4))
    cellular_firewall_destination_octet = int(session_data.get('cellular_firewall_destination_octet', 4))
    one_to_many_nat_lan_ip_octet = int(session_data.get('one_to_many_nat_lan_ip_octet', 4))
    one_to_one_nat_lan_ip_octet = int(session_data.get('one_to_one_nat_lan_ip_octet', 4))
    inbound_firewall_source_octet = int(session_data.get('inbound_firewall_source_octet', 4))
    inbound_firewall_destination_octet = int(session_data.get('inbound_firewall_destination_octet', 4))
    port_forwarding_lan_ip_octet = int(session_data.get('port_forwarding_lan_ip_octet', 4))
    vlans_subnet_octet = int(session_data.get('vlans_subnet_octet', 4))
    
    # Get product type information
    network_product_types = session_data.get('network_product_types', {})
    golden_product_types = session_data.get('golden_product_types', {'has_mx': True, 'has_ms': True, 'has_mr': True})
    
    # Create dashboard instance
    dashboard = meraki.DashboardAPI(api_key, output_log=False)
    
    # Initialize tables
    summary_table = PrettyTable()
    summary_table.field_names = ["Organization", "Network", "Check", "Status"]
    
    non_compliant_networks_table = PrettyTable()
    non_compliant_networks_table.field_names = ["Organization", "Network", "Check", "Details"]
    
    verdict_table = PrettyTable()
    verdict_table.field_names = ["Organization", "Network", "Check", "Verdict"]
    
    network_verdicts = {}
    
    # Define the complete list of template-unsupported endpoints
    template_unsupported_endpoints = [
        'getNetworkApplianceWarmSpare',
        'getNetworkApplianceVpnSiteToSiteVpn',
        'getNetworkSwitchRoutingOspf',
        'getNetworkSwitchStormControl', 
        'getNetworkSwitchDhcpServerPolicy',
        'getNetworkAppliancePorts',
        'getNetworkApplianceVlans',
        'getNetworkWirelessSsidFirewallL3FirewallRules',
        'getNetworkWirelessSsidFirewallL7FirewallRules',
        'getNetworkWirelessSsidTrafficShapingRules',
        'getNetworkWirelessSsidIdentityPsks',
        'getNetworkWirelessEthernetPortsProfiles',
        'getNetworkWirelessBluetoothSettings'
    ]
    
    check_name_mapping = {
    # MX Checks
    "getNetworkApplianceConnectivityMonitoringDestinations": "Connectivity Monitoring Destinations",
    "getNetworkApplianceContentFiltering": "Content Filtering",
    "getNetworkApplianceFirewallSettings": "Firewall Settings",
    "getNetworkApplianceFirewallCellularFirewallRules": "Cellular Firewall Rules",
    "getNetworkApplianceFirewallInboundCellularFirewallRules": "Inbound Cellular Firewall Rules",
    "getNetworkApplianceFirewallL3FirewallRules": "L3 Firewall Rules",
    "getNetworkApplianceFirewallFirewalledServices": "Firewalled Services",
    "getNetworkApplianceFirewallInboundFirewallRules": "Inbound Firewall Rules",
    "getNetworkApplianceFirewallL7FirewallRules": "L7 Firewall Rules",
    "getNetworkApplianceFirewallOneToManyNatRules": "One-to-Many NAT Rules",
    "getNetworkApplianceFirewallOneToOneNatRules": "One-to-One NAT Rules",
    "getNetworkApplianceFirewallPortForwardingRules": "Port Forwarding Rules",
    "getNetworkAppliancePorts": "Appliance Ports",
    "getNetworkApplianceSecurityIntrusion": "Security Intrusion Settings",
    "getNetworkApplianceSecurityMalware": "Security Malware Settings",
    "getNetworkApplianceSingleLan": "Single LAN Configuration",
    "getNetworkApplianceStaticRoutes": "Static Routes",
    "getNetworkApplianceTrafficShaping": "Traffic Shaping",
    "getNetworkApplianceTrafficShapingCustomPerformanceClasses": "Traffic Shaping Custom Classes",
    "getNetworkApplianceTrafficShapingRules": "Traffic Shaping Rules",
    "getNetworkApplianceTrafficShapingUplinkBandwidth": "Uplink Bandwidth",
    "getNetworkApplianceTrafficShapingUplinkSelection": "Uplink Selection",
    "getNetworkApplianceVlans": "VLANs",
    "getNetworkApplianceVpnSiteToSiteVpn": "Site-to-Site VPN",
    "getNetworkApplianceWarmSpare": "Warm Spare",
    "getNetworkApplianceSettings": "Appliance Settings",
    "getOrganizationApplianceVpnThirdPartyVPNPeers": "Third-Party VPN Peers",

    # MS Checks
    "getNetworkSwitchAccessControlLists": "Switch ACLs",
    "getNetworkSwitchDhcpServerPolicy": "DHCP Server Policy",
    "getNetworkSwitchDscpToCosMappings": "DSCP to CoS Mappings",
    "getNetworkSwitchMtu": "Switch MTU",
    "getNetworkSwitchPortSchedules": "Port Schedules",
    "getNetworkSwitchQosRules": "QoS Rules",
    "getNetworkSwitchRoutingOspf": "OSPF Routing",
    "getNetworkSwitchSettings": "Switch Settings",
    "getNetworkSwitchStormControl": "Storm Control",
    "getNetworkSwitchStp": "Spanning Tree Protocol",

    # MR Checks
    "getNetworkWirelessSsids": "Wireless SSIDs",
    "getNetworkWirelessRfProfiles": "RF Profiles",
    "getNetworkWirelessSettings": "Wireless Settings",
    "getNetworkWirelessBilling": "Wireless Billing",
    "getNetworkWirelessAlternateManagementInterface": "Alternate Management Interface",
    "getNetworkWirelessBluetoothSettings": "Bluetooth Settings",
    "getNetworkWirelessEthernetPortsProfiles": "Ethernet Ports Profiles",
    "getNetworkWirelessSsidFirewallL3FirewallRules": "SSID L3 Firewall Rules",
    "getNetworkWirelessSsidFirewallL7FirewallRules": "SSID L7 Firewall Rules",
    "getNetworkWirelessSsidTrafficShapingRules": "SSID Traffic Shaping Rules",
    "getNetworkWirelessSsidIdentityPsks": "SSID Identity PSKs"
    }
    
    # Create a mapping from check names to comparison functions
    comparison_functions = {
        # MX Checks
        "getNetworkApplianceConnectivityMonitoringDestinations": compare_connectivity_monitoring,
        "getNetworkApplianceContentFiltering": compare_content_filtering,
        "getNetworkApplianceFirewallSettings": deep_compare,  # Often uses deep_compare if no specialized function
        "getNetworkApplianceFirewallCellularFirewallRules": compare_cellular_firewall_rules,
        "getNetworkApplianceFirewallInboundCellularFirewallRules": deep_compare,  # Similar to cellular rules
        "getNetworkApplianceFirewallL3FirewallRules": compare_l3_firewall_rules,
        "getNetworkApplianceFirewallFirewalledServices": deep_compare,
        "getNetworkApplianceFirewallInboundFirewallRules": compare_inbound_firewall_rules,
        "getNetworkApplianceFirewallL7FirewallRules": compare_l7_firewall_rules,
        "getNetworkApplianceFirewallOneToManyNatRules": 
        lambda g, n, octet=one_to_many_nat_lan_ip_octet: compare_one_to_many_nat_rules(g, n, octet),
        "getNetworkApplianceFirewallOneToOneNatRules": compare_one_to_one_nat_rules,
        "getNetworkApplianceFirewallPortForwardingRules": compare_port_forwarding_rules,
        "getNetworkAppliancePorts": compare_appliance_ports,
        "getNetworkApplianceSecurityIntrusion": compare_security_intrusion,
        "getNetworkApplianceSecurityMalware": compare_security_malware,
        "getNetworkApplianceSingleLan": deep_compare,
        "getNetworkApplianceStaticRoutes": compare_static_routes,
        "getNetworkApplianceTrafficShaping": deep_compare,
        "getNetworkApplianceTrafficShapingCustomPerformanceClasses": deep_compare,
        "getNetworkApplianceTrafficShapingRules": deep_compare,
        "getNetworkApplianceTrafficShapingUplinkBandwidth": deep_compare,
        "getNetworkApplianceTrafficShapingUplinkSelection": deep_compare,
        "getNetworkApplianceVlans": compare_vlans,
        "getNetworkApplianceVpnSiteToSiteVpn": compare_site_to_site_vpn,
        "getNetworkApplianceWarmSpare": compare_warm_spare,
        "getNetworkApplianceSettings": compare_appliance_settings,
        "getOrganizationApplianceVpnThirdPartyVPNPeers": deep_compare,

        # MS Checks
        "getNetworkSwitchAccessControlLists": compare_switch_acls,
        "getNetworkSwitchDhcpServerPolicy": compare_switch_dhcp_server_policy,
        "getNetworkSwitchDscpToCosMappings": compare_switch_dscp_to_cos,
        "getNetworkSwitchMtu": compare_switch_mtu,
        "getNetworkSwitchPortSchedules": compare_switch_port_schedules,
        "getNetworkSwitchQosRules": compare_switch_qos_rules,
        "getNetworkSwitchRoutingOspf": deep_compare,
        "getNetworkSwitchSettings": compare_switch_settings,
        "getNetworkSwitchStormControl": compare_switch_storm_control,
        "getNetworkSwitchStp": compare_switch_stp,

        # MR Checks
        "getNetworkWirelessSsids": compare_wireless_ssids,
        "getNetworkWirelessRfProfiles": compare_wireless_rf_profiles,
        "getNetworkWirelessSettings": compare_wireless_settings,
        "getNetworkWirelessBilling": deep_compare,
        "getNetworkWirelessAlternateManagementInterface": compare_wireless_features,
        "getNetworkWirelessBluetoothSettings": compare_wireless_features,
        "getNetworkWirelessEthernetPortsProfiles": deep_compare,
        "getNetworkWirelessSsidFirewallL3FirewallRules": compare_wireless_ssid_l3_firewall_rules,
        "getNetworkWirelessSsidFirewallL7FirewallRules": compare_wireless_ssid_l7_firewall_rules,
        "getNetworkWirelessSsidTrafficShapingRules": compare_wireless_ssid_traffic_shaping_rules,
        "getNetworkWirelessSsidIdentityPsks": compare_wireless_ssid_identity_psks
    }
    
    # Get org names
    try:
        org_names = {}
        for org_id in orgs:
            org_info = dashboard.organizations.getOrganization(org_id)
            org_names[org_id] = org_info['name']
    except Exception as e:
        logging.error(f"Error getting organization names: {e}")
        raise
    
    # Process each organization
    for org_id in orgs:
        org_name = org_names.get(org_id, org_id)  # Use ID as fallback if name not found
        golden_network_id = golden_images[org_id]
        networks_to_check = compliance_networks[org_id]
        
        # Determine if golden image is a template
        is_golden_template = golden_network_id in template_ids
        
        # Load golden image data
        try:
            # For templates, adjust the path
            if is_golden_template:
                templates = dashboard.organizations.getOrganizationConfigTemplates(org_id)
                golden_template = next((t for t in templates if t['id'] == golden_network_id), None)
                if golden_template:
                    golden_network_name = golden_template['name'] + ' (Template)'
                else:
                    golden_network_name = "Template_" + golden_network_id
            else:
                golden_network_info = dashboard.networks.getNetwork(golden_network_id)
                golden_network_name = golden_network_info['name']
                
            golden_directory = f"Org_{org_name.replace(' ', '_')}/{org_name.replace(' ', '_')}_{golden_network_name.replace(' ', '_')}_GoldenImage"
            golden_data = load_json(os.path.join(golden_directory, 'golden_image_data.json'))
        except Exception as e:
            logging.error(f"Error loading golden image data for org {org_name}: {e}")
            continue

        # Process each network to check
        for network_id in networks_to_check:
            try:
                non_compliant_checks = []
                
                # Determine if network is a template
                is_network_template = network_id in template_ids
                
                # Get network name
                if is_network_template:
                    templates = dashboard.organizations.getOrganizationConfigTemplates(org_id)
                    network_template = next((t for t in templates if t['id'] == network_id), None)
                    if network_template:
                        network_name = network_template['name'] + ' (Template)'
                    else:
                        network_name = "Template_" + network_id
                else:
                    network_info = dashboard.networks.getNetwork(network_id)
                    network_name = network_info['name']
                
                network_directory = f"Org_{org_name.replace(' ', '_')}/{network_name.replace(' ', '_')}_ComplianceCheck"
                network_data = load_json(os.path.join(network_directory, 'network_data.json'))
                
                # Get product types for this network
                if is_network_template:
                    # For templates, assume all product types
                    network_product_type = {'has_mx': True, 'has_ms': True, 'has_mr': True}
                else:
                    network_product_type = network_product_types.get(network_id, {'has_mx': True, 'has_ms': True, 'has_mr': False})
                
                # Filter checks based on product types
                applicable_mx_checks = mx_checks if (golden_product_types.get('has_mx', True) and network_product_type.get('has_mx', True)) else []
                applicable_ms_checks = ms_checks if (golden_product_types.get('has_ms', True) and network_product_type.get('has_ms', True)) else []
                applicable_mr_checks = mr_checks if (golden_product_types.get('has_mr', True) and network_product_type.get('has_mr', True)) else []
                
                # Skip SSID-specific checks for templates
                if is_golden_template or is_network_template:
                    applicable_mr_checks = [check for check in applicable_mr_checks if not check.startswith('getNetworkWirelessSsid')]
                
                # Process all applicable checks
                all_checks = applicable_mx_checks + applicable_ms_checks + applicable_mr_checks
                
                # Process wireless checks only if MR exists in both networks
                has_wireless = golden_product_types.get('has_mr', False) and network_product_type.get('has_mr', False)
                
                # Process each check
                for check in all_checks:
                    # Get the user-friendly name from the mapping dictionary - use the API name as fallback
                    user_friendly_name = check_name_mapping.get(check, check)
                    
                    # Skip MR checks if wireless is not enabled in the network
                    if check.startswith('getNetworkWireless') and not has_wireless:
                        summary_table.add_row([org_name, network_name, user_friendly_name, "Not Applicable"])
                        verdict_table.add_row([org_name, network_name, user_friendly_name, "Not Applicable - No Wireless"])
                        continue
                    
                    if check in template_unsupported_endpoints and (is_golden_template or is_network_template):
                        summary_table.add_row([org_name, network_name, user_friendly_name, "Not Applicable"])
                        verdict_table.add_row([org_name, network_name, user_friendly_name, 
                                           "Not Applicable - Unsupported for templates"])
                        continue

                    
                    try:
                        # Get the relevant data for this check
                        golden_check_data, network_check_data = get_check_data(golden_data, network_data, check)
                        check_key = check.replace('getNetwork', '').replace('getOrganization', '').replace('Appliance', '').replace('Switch', '').lower()
                        
                        # Check for explicit "Not supported for templates" message (handle both formats)
                        if ((isinstance(golden_check_data.get(check_key), str) and 
                             ("Not Applicable - Unsupported for templates" in golden_check_data.get(check_key) or 
                              "Not supported for templates" in golden_check_data.get(check_key))) or
                            (isinstance(network_check_data.get(check_key), str) and 
                             ("Not Applicable - Unsupported for templates" in network_check_data.get(check_key) or 
                              "Not supported for templates" in network_check_data.get(check_key)))):
                            
                            summary_table.add_row([org_name, network_name, user_friendly_name, "Not Applicable"])
                            verdict_table.add_row([org_name, network_name, user_friendly_name, 
                                               "Not Applicable - Unsupported for templates"])
                            continue
                        
                        # Handle the case where both golden and network are None
                        if ((golden_check_data.get(check_key) is None or golden_check_data.get(check_key) == {}) and 
                            (network_check_data.get(check_key) is None or network_check_data.get(check_key) == {})):
                            logging.debug(f"No data for {check}: Both golden and network data are None or empty")
                            # If either is a template and this check is typically unsupported, mark as Not Applicable
                            if check in template_unsupported_endpoints and (is_golden_template or is_network_template):
                                summary_table.add_row([org_name, network_name, user_friendly_name, "Not Applicable"])
                                verdict_table.add_row([org_name, network_name, user_friendly_name, 
                                                  "Not Applicable - Unsupported for templates"])
                            else:
                                # Otherwise, if both are None, they are compliant (neither configured)
                                summary_table.add_row([org_name, network_name, user_friendly_name, "Compliant"])
                                verdict_table.add_row([org_name, network_name, user_friendly_name, "Compliant"])
                            continue
                        
                        # Handle golden=None, network=value
                        if (golden_check_data.get(check_key) is None or golden_check_data.get(check_key) == {}) and (network_check_data.get(check_key) is not None and network_check_data.get(check_key) != {}):
                            # If golden is a template and this check is typically unsupported
                            if is_golden_template and check in template_unsupported_endpoints:
                                summary_table.add_row([org_name, network_name, user_friendly_name, "Not Applicable"])
                                verdict_table.add_row([org_name, network_name, user_friendly_name, 
                                                  "Not Applicable - Unsupported for templates"])
                                continue
                        
                        # Handle golden=value, network=None
                        if (golden_check_data.get(check_key) is not None and golden_check_data.get(check_key) != {}) and (network_check_data.get(check_key) is None or network_check_data.get(check_key) == {}):
                            # If network is a template and this check is typically unsupported
                            if is_network_template and check in template_unsupported_endpoints:
                                summary_table.add_row([org_name, network_name, user_friendly_name, "Not Applicable"])
                                verdict_table.add_row([org_name, network_name, user_friendly_name, 
                                                  "Not Applicable - Unsupported for templates"])
                                continue
                        
                        # Use the appropriate comparison function with error handling
                        try:
                            if check in comparison_functions:
                                result = comparison_functions[check](golden_check_data, network_check_data)
                                if isinstance(result, tuple):
                                    is_compliant, reason = result
                                else:
                                    is_compliant = result
                                    reason = None
                            else:
                                # Fallback to deep comparison for checks without specialized functions
                                logging.debug(f"Using deep comparison for {check}")
                                is_compliant = deep_compare(golden_check_data, network_check_data)
                                reason = None
                        except Exception as e:
                            logging.error(f"Error in comparison function for {check}: {e}")
                            summary_table.add_row([org_name, network_name, user_friendly_name, "Error"])
                            verdict_table.add_row([org_name, network_name, user_friendly_name, f"Error in comparison: {e}"])
                            continue
                        
                        # Record the result
                        if is_compliant:
                            summary_table.add_row([org_name, network_name, user_friendly_name, "Compliant"])
                            verdict_table.add_row([org_name, network_name, user_friendly_name, "Compliant"])
                        else:
                            verdict_message = "Non-Compliant"
                            if reason:
                                verdict_message = f"Non-Compliant: {reason}"
                            
                            summary_table.add_row([org_name, network_name, user_friendly_name, "Non-Compliant"])
                            non_compliant_networks_table.add_row([org_name, network_name, user_friendly_name, 
                                                               f"Golden: {golden_check_data}, Network: {network_check_data}"])
                            verdict_table.add_row([org_name, network_name, user_friendly_name, verdict_message])
                            non_compliant_checks.append(check)
                    except Exception as e:
                        logging.error(f"Error processing check {check}: {e}")
                        summary_table.add_row([org_name, network_name, user_friendly_name, "Error"])
                        verdict_table.add_row([org_name, network_name, user_friendly_name, f"Error: {e}"])
                        
                # Update the network verdict
                network_verdicts[(org_name, network_name)] = "Compliant" if not non_compliant_checks else "Non-Compliant"
            except Exception as e:
                logging.error(f"Error processing network {network_id}: {e}")
                continue

    # Create the network verdict table
    network_verdict_table = PrettyTable()
    network_verdict_table.field_names = ["Organization", "Network", "Verdict"]

    # Add non-compliant networks first
    for (org_name, network_name), verdict in network_verdicts.items():
        if verdict == "Non-Compliant":
            network_verdict_table.add_row([org_name, network_name, verdict])

    # Add compliant networks
    for (org_name, network_name), verdict in network_verdicts.items():
        if verdict == "Compliant":
            network_verdict_table.add_row([org_name, network_name, verdict])
    # AI-enhanced analysis
    try:
        # Prepare data for AI analysis
        all_configs = {}
        network_names = {}
        
        # Collect network configurations
        for org_id in orgs:
            org_name = org_names.get(org_id, org_id)
            # Get golden image data
            golden_network_id = golden_images[org_id]
            golden_dir = f"Org_{org_name.replace(' ', '_')}/{org_name.replace(' ', '_')}_{golden_network_name.replace(' ', '_')}_GoldenImage"
            try:
                with open(os.path.join(golden_dir, 'golden_image_data.json'), 'r') as f:
                    all_configs[golden_network_id] = json.load(f)
                    network_names[golden_network_id] = golden_network_name
            except Exception as e:
                logging.warning(f"Could not load golden image data for {org_id}: {e}")
            
            # Collect checked networks data
            for network_id in compliance_networks.get(org_id, []):
                network_dir = f"Org_{org_name.replace(' ', '_')}/{network_name.replace(' ', '_')}_ComplianceCheck"
                try:
                    with open(os.path.join(network_dir, 'network_data.json'), 'r') as f:
                        all_configs[network_id] = json.load(f)
                        network_names[network_id] = network_name
                except Exception as e:
                    logging.warning(f"Could not load network data for {network_id}: {e}")
        
        # Extract non-compliant networks info
        logging.debug("Extracting non-compliant network data")
        non_compliant_results = extract_non_compliant_data(
            network_verdicts, 
            verdict_table, 
            check_name_mapping, 
            network_names, 
            compliance_networks
        )
        
        # Run anomaly detection
        logging.debug("Running anomaly detection")
        anomalies = detect_meraki_anomalies(all_configs, org_names=org_names, network_names=network_names)
        
        # Generate recommendations
        logging.debug("Generating compliance recommendations")
        golden_configs = {org_id: all_configs.get(golden_images.get(org_id)) for org_id in orgs}
        recommendations = generate_compliance_recommendations(golden_configs, all_configs, non_compliant_results)
        
        # Log analysis results
        logging.info(f"Anomalies found: {len(anomalies)}")
        logging.info(f"Recommendations generated: {sum(len(recs) for recs in recommendations.values())}")
        
        # Save analysis results
        with open('anomalies.json', 'w') as file:
            json.dump(anomalies, file, indent=4)
        logging.debug(f"Saved anomalies to anomalies.json")
        
        with open('recommendations.json', 'w') as file:
            json.dump(recommendations, file, indent=4)
        logging.debug(f"Saved recommendations to recommendations.json")
        # Save check name mapping for the report generation
        with open('check_name_mapping.json', 'w') as file:
            json.dump(check_name_mapping, file, indent=4)
        logging.debug(f"Saved check name mapping to check_name_mapping.json")
    except Exception as e:
        logging.error(f"Error in AI analysis: {e}")
        logging.error(traceback.format_exc())

    # Save tables to files
    save_prettytable_to_file(summary_table, 'summary_table.txt')
    save_prettytable_to_file(non_compliant_networks_table, 'non_compliant_networks_table.txt')
    save_prettytable_to_file(verdict_table, 'verdict_table.txt')
    save_prettytable_to_file(network_verdict_table, 'network_verdict_table.txt')
    
    logging.debug("Compliance check completed")
    return True
def run_compliance_check_wrapper():
    """
    Wrapper function to safely run the compliance check and handle any exceptions
    """
    try:
        logging.debug("Starting compliance check")
        result = run_compliance_check()
        logging.debug("Compliance check completed")
        return result
    except Exception as e:
        logging.error(f"Error in compliance check: {e}")
        # Create minimal tables with error information
        summary_table = PrettyTable()
        summary_table.field_names = ["Status", "Error"]
        summary_table.add_row(["Error", str(e)])
        
        save_prettytable_to_file(summary_table, 'summary_table.txt')
        save_prettytable_to_file(summary_table, 'non_compliant_networks_table.txt')
        save_prettytable_to_file(summary_table, 'verdict_table.txt')
        save_prettytable_to_file(summary_table, 'network_verdict_table.txt')
        
        return f"Error in compliance check: {e}"
    finally:
        logging.debug("Compliance check completed")

if __name__ == "__main__":
    run_compliance_check_wrapper()
    