import asyncio
import meraki.aio
import os
import json
import logging
import csv

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def print_colored(message, color):
    colors = {
        'green': '\033[92m',  # Green text
        'red': '\033[91m',    # Red text
        'purple': '\033[95m', # Purple text
    }
    reset_code = '\033[0m'  # Reset to default text color
    print(f"{colors.get(color, '')}{message}{reset_code}")

def save_to_json(directory, filename, data):
    filepath = os.path.join(directory, filename)
    with open(filepath, 'w') as file:
        json.dump(data, file, indent=4)
    logging.debug(f"Saved data to {filepath}")

def save_to_csv(directory, filename, data):
    filepath = os.path.join(directory, filename)
    with open(filepath, 'w', newline='') as file:
        writer = csv.writer(file)
        if isinstance(data, list):
            if len(data) > 0 and isinstance(data[0], dict):
                writer.writerow(data[0].keys())
                for row in data:
                    writer.writerow(row.values())
            else:
                writer.writerow(['Value'])
                for row in data:
                    writer.writerow([row])
        elif isinstance(data, dict):
            writer.writerow(data.keys())
            writer.writerow(data.values())
        else:
            writer.writerow(['Value'])
            writer.writerow([data])
    logging.debug(f"Saved data to {filepath}")

async def fetch_ssid_specific_data(dashboard, network_id, check, data_dict, retries=3):
    """Special handling for SSID-specific endpoints that require SSID number parameter"""
    
    # Extract key from check name
    key = check.replace('getNetwork', '').replace('Wireless', '').replace('Ssid', '').lower()
    
    # First get all SSIDs 
    try:
        ssids = await dashboard.wireless.getNetworkWirelessSsids(network_id)
        
        # Initialize container for this check
        data_dict[key] = {}
        
        # Loop through enabled SSIDs
        for ssid in ssids:
            ssid_number = ssid['number']
            if ssid['enabled']:
                for attempt in range(retries):
                    try:
                        # Call the appropriate API with the SSID number
                        if check == 'getNetworkWirelessSsidFirewallL3FirewallRules':
                            response = await asyncio.wait_for(
                                dashboard.wireless.getNetworkWirelessSsidFirewallL3FirewallRules(
                                    network_id, ssid_number
                                ), 
                                timeout=10
                            )
                        elif check == 'getNetworkWirelessSsidFirewallL7FirewallRules':
                            response = await asyncio.wait_for(
                                dashboard.wireless.getNetworkWirelessSsidFirewallL7FirewallRules(
                                    network_id, ssid_number
                                ),
                                timeout=10
                            )
                        elif check == 'getNetworkWirelessSsidTrafficShapingRules':
                            response = await asyncio.wait_for(
                                dashboard.wireless.getNetworkWirelessSsidTrafficShapingRules(
                                    network_id, ssid_number
                                ),
                                timeout=10
                            )
                        elif check == 'getNetworkWirelessSsidIdentityPsks':
                            response = await asyncio.wait_for(
                                dashboard.wireless.getNetworkWirelessSsidIdentityPsks(
                                    network_id, ssid_number
                                ),
                                timeout=10
                            )
                        
                        # Store response for this SSID
                        data_dict[key][ssid_number] = response
                        logging.debug(f"Fetched {key} data for SSID {ssid_number}")
                        break  # Success, exit retry loop
                        
                    except asyncio.TimeoutError:
                        logging.error(f"Timeout fetching {key} data for SSID {ssid_number}, attempt {attempt + 1}")
                    except meraki.aio.AsyncAPIError as e:
                        if str(e.status).startswith('4'):
                            data_dict[key][ssid_number] = None
                            logging.debug(f"4xx error for {key} SSID {ssid_number}: {e}")
                            break  # No retry for 4xx errors
                        else:
                            logging.error(f"API Error for {key} SSID {ssid_number}: {e}, attempt {attempt + 1}")
                    except Exception as e:
                        logging.error(f"Unexpected error for {key} SSID {ssid_number}: {e}, attempt {attempt + 1}")
                    
                    # If we've reached max retries
                    if attempt == retries - 1:
                        data_dict[key][ssid_number] = "Data Collection Failed"
                        logging.error(f"Failed to fetch {key} data for SSID {ssid_number} after {retries} attempts")
                    
        logging.debug(f"Fetched data for {key}")
        
    except Exception as e:
        logging.error(f"Error fetching SSIDs for {check}: {e}")
        data_dict[key] = {"error": str(e)}
async def fetch_template_data(dashboard, template_id, org_id, check, data_dict, retries=3):
    """Special handling for template configuration endpoints"""
    key = check.replace('getNetwork', '').replace('getOrganization', '').replace('Appliance', '').replace('Switch', '').lower()
    
    # Comprehensive list of template-unsupported endpoints
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
    
    # Check if this endpoint is unsupported for templates
    if check in template_unsupported_endpoints:
        data_dict[key] = "Not Applicable - Unsupported for templates"
        logging.debug(f"Skipping unsupported check {check} for template")
        return
    
    # Special handling for wireless operations in templates
    if check.startswith('getNetworkWirelessSsid'):
        data_dict[key] = "Not Applicable - Unsupported for templates"
        logging.debug(f"Skipping SSID-specific check {check} for template")
        return
            
    # For supported template endpoints, call the regular fetch_data function
    await fetch_data(dashboard, template_id, org_id, check, data_dict, retries)

async def fetch_data(dashboard, network_id, org_id, check, data_dict, retries=3):
    """
    Generic function to fetch data from Meraki API
    
    Args:
        dashboard: Meraki API dashboard instance
        network_id: ID of the network to fetch data for
        org_id: ID of the organization
        check: API function to call (e.g., 'getNetworkApplianceVlans')
        data_dict: Dictionary to store results
        retries: Number of retry attempts
    """
    # Extract key from check name (e.g., 'getNetworkApplianceVlans' -> 'vlans')
    key = check.replace('getNetwork', '').replace('getOrganization', '').replace('Appliance', '').replace('Switch', '').lower()
    
    for attempt in range(retries):
        try:
            # Call the appropriate API method based on whether it's an org or network level call
            # and whether it's an appliance, switch, or wireless API call
            if check.startswith('getOrganization'):
                if 'Appliance' in check:
                    response = await asyncio.wait_for(getattr(dashboard.appliance, check)(org_id), timeout=10)
                elif 'Switch' in check:
                    response = await asyncio.wait_for(getattr(dashboard.switch, check)(org_id), timeout=10)
                elif 'Wireless' in check:
                    response = await asyncio.wait_for(getattr(dashboard.wireless, check)(org_id), timeout=10)
                else:
                    response = await asyncio.wait_for(getattr(dashboard.organizations, check)(org_id), timeout=10)
            else:
                if 'Appliance' in check:
                    response = await asyncio.wait_for(getattr(dashboard.appliance, check)(network_id), timeout=10)
                elif 'Switch' in check:
                    response = await asyncio.wait_for(getattr(dashboard.switch, check)(network_id), timeout=10)
                elif 'Wireless' in check:
                    response = await asyncio.wait_for(getattr(dashboard.wireless, check)(network_id), timeout=10)
                else:
                    response = await asyncio.wait_for(getattr(dashboard.networks, check)(network_id), timeout=10)
                
            if response:
                data_dict[key] = response
                logging.debug(f"Fetched data for {key}")
            else:
                data_dict[key] = None
                logging.debug(f"No data for {key}")
            return
        except asyncio.TimeoutError:
            logging.error(f"Timeout fetching data for {key}, attempt {attempt + 1}")
        except meraki.aio.AsyncAPIError as e:
            if str(e.status).startswith('4'):
                data_dict[key] = None
                logging.debug(f"4xx error for {key}: {e}")
                return
            else:
                logging.error(f"API Error for {key}: {e}, attempt {attempt + 1}")
        except Exception as e:
            logging.error(f"Unexpected error for {key}: {e}, attempt {attempt + 1}")
            
    data_dict[key] = "Data Collection Failed"
    logging.error(f"Failed to fetch data for {key} after {retries} attempts")
async def get_network_product_types(dashboard, network_id):
    """
    Determine which product types (MX, MS, MR) are present in a network.
    
    Args:
        dashboard: Meraki API dashboard instance
        network_id: Network ID to check
        
    Returns:
        dict: Dictionary with boolean values for 'has_mx', 'has_ms', 'has_mr'
    """
    try:
        devices = await dashboard.networks.getNetworkDevices(network_id)
        
        # Initialize product type flags
        product_types = {
            'has_mx': False,
            'has_ms': False,
            'has_mr': False
        }
        
        # Check each device's model to determine product types
        for device in devices:
            model = device.get('model', '')
            if model.startswith('MX'):
                product_types['has_mx'] = True
            elif model.startswith('MS'):
                product_types['has_ms'] = True
            elif model.startswith('MR'):
                product_types['has_mr'] = True
                
        # Check network details to handle virtual MXs and networks without devices
        network_details = await dashboard.networks.getNetwork(network_id)
        product_types_from_network = network_details.get('productTypes', [])
        
        if 'appliance' in product_types_from_network:
            product_types['has_mx'] = True
        if 'switch' in product_types_from_network:
            product_types['has_ms'] = True
        if 'wireless' in product_types_from_network:
            product_types['has_mr'] = True
            
        logging.debug(f"Product types for network {network_id}: {product_types}")
        return product_types
        
    except Exception as e:
        logging.error(f"Error determining product types for network {network_id}: {e}")
        # Default to assuming no product types to avoid running checks that might fail
        return {'has_mx': False, 'has_ms': False, 'has_mr': False}

async def gatherinfo(api_key, orgs, mx_checks, ms_checks, mr_checks, golden_images, compliance_networks, 
                    l3_firewall_source_octet, l3_firewall_destination_octet, 
                    cellular_firewall_source_octet, cellular_firewall_destination_octet, 
                    one_to_many_nat_lan_ip_octet, one_to_one_nat_lan_ip_octet, 
                    inbound_firewall_source_octet, inbound_firewall_destination_octet, 
                    port_forwarding_lan_ip_octet, vlans_subnet_octet, template_ids=None):
    
    if template_ids is None:
        template_ids = []
    
    async with meraki.aio.AsyncDashboardAPI(api_key=api_key, output_log=False, print_console=False, suppress_logging=True) as dashboard:
        org_names = {}
        network_product_types = {}
        
        # Process each organization
        for org_id in orgs:
            try:
                # Get organization info
                org_info = await dashboard.organizations.getOrganization(org_id)
                org_name = org_info['name']
                org_names[org_id] = org_name
                golden_network_id = golden_images[org_id]
                networks_to_check = compliance_networks[org_id]

                # Create organization directory
                org_directory = f"Org_{org_name.replace(' ', '_')}"
                os.makedirs(org_directory, exist_ok=True)
                logging.debug(f"Created directory {org_directory}")

                # Process the golden image network
                golden_data = {}
                is_golden_template = golden_network_id in template_ids
                
                # Get network/template info
                if is_golden_template:
                    # For templates, get template info
                    logging.debug(f"Golden image is a template: {golden_network_id}")
                    templates = await dashboard.organizations.getOrganizationConfigTemplates(org_id)
                    golden_template = next((t for t in templates if t['id'] == golden_network_id), None)
                    if golden_template:
                        golden_network_name = golden_template['name'] + ' (Template)'
                    else:
                        # Fallback if template not found
                        golden_network_name = "Template_" + golden_network_id
                else:
                    # For regular networks, get network info
                    golden_network_info = await dashboard.networks.getNetwork(golden_network_id)
                    golden_network_name = golden_network_info['name']
                
                golden_directory = os.path.join(org_directory, f"{org_name.replace(' ', '_')}_{golden_network_name.replace(' ', '_')}_GoldenImage")
                os.makedirs(golden_directory, exist_ok=True)
                logging.debug(f"Created directory {golden_directory}")

                # Detect product types (only for regular networks)
                if not is_golden_template:
                    golden_product_types = await get_network_product_types(dashboard, golden_network_id)
                    logging.debug(f"Golden network {golden_network_id} product types: {golden_product_types}")
                else:
                    # For templates, assume all product types are present
                    golden_product_types = {'has_mx': True, 'has_ms': True, 'has_mr': True}

                # Fetch data for the golden image
                for check in mx_checks:
                    try:
                        if is_golden_template:
                            await fetch_template_data(dashboard, golden_network_id, org_id, check, golden_data)
                        else:
                            await fetch_data(dashboard, golden_network_id, org_id, check, golden_data)
                    except Exception as e:
                        logging.error(f"Error in golden network MX check {check}: {e}")
                        
                for check in ms_checks:
                    try:
                        if is_golden_template:
                            await fetch_template_data(dashboard, golden_network_id, org_id, check, golden_data)
                        else:
                            await fetch_data(dashboard, golden_network_id, org_id, check, golden_data)
                    except Exception as e:
                        logging.error(f"Error in golden network MS check {check}: {e}")
                        
                for check in mr_checks:
                    try:
                        if is_golden_template:
                            if check in ['getNetworkWirelessSsidFirewallL3FirewallRules', 
                                       'getNetworkWirelessSsidFirewallL7FirewallRules',
                                       'getNetworkWirelessSsidTrafficShapingRules',
                                       'getNetworkWirelessSsidIdentityPsks']:
                                # Skip SSID-specific checks for templates
                                logging.debug(f"Skipping SSID-specific check {check} for template")
                                continue
                            await fetch_template_data(dashboard, golden_network_id, org_id, check, golden_data)
                        else:
                            if check in ['getNetworkWirelessSsidFirewallL3FirewallRules', 
                                       'getNetworkWirelessSsidFirewallL7FirewallRules',
                                       'getNetworkWirelessSsidTrafficShapingRules',
                                       'getNetworkWirelessSsidIdentityPsks']:
                                await fetch_ssid_specific_data(dashboard, golden_network_id, check, golden_data)
                            else:
                                await fetch_data(dashboard, golden_network_id, org_id, check, golden_data)
                    except Exception as e:
                        logging.error(f"Error in golden network MR check {check}: {e}")

                # Save golden image data
                save_to_json(golden_directory, 'golden_image_data.json', golden_data)
                save_to_csv(golden_directory, 'golden_image_data.csv', golden_data)
                logging.debug(f"Golden image data saved for network {golden_network_id}")

                # Process each network to check
                for network_id in networks_to_check:
                    try:
                        is_network_template = network_id in template_ids
                        
                        # Get network/template data
                        if is_network_template:
                            logging.debug(f"Network to check is a template: {network_id}")
                            templates = await dashboard.organizations.getOrganizationConfigTemplates(org_id)
                            network_template = next((t for t in templates if t['id'] == network_id), None)
                            if network_template:
                                network_name = network_template['name'] + ' (Template)'
                            else:
                                # Fallback if template not found
                                network_name = "Template_" + network_id
                        else:
                            # Detect product types in this network (only for regular networks)
                            network_info = await dashboard.networks.getNetwork(network_id)
                            network_name = network_info['name']
                            
                            # Get product types
                            network_product_type = await get_network_product_types(dashboard, network_id)
                            network_product_types[network_id] = network_product_type
                            logging.debug(f"Network {network_id} product types: {network_product_type}")
                        
                        # For templates, assume all product types
                        if is_network_template:
                            network_product_types[network_id] = {'has_mx': True, 'has_ms': True, 'has_mr': True}
                        
                        # Create directory for this network
                        network_directory = os.path.join(org_directory, f"{network_name.replace(' ', '_')}_ComplianceCheck")
                        os.makedirs(network_directory, exist_ok=True)
                        logging.debug(f"Created directory {network_directory}")

                        # Fetch network configuration data
                        network_data = {}
                        
                        # MX checks
                        for check in mx_checks:
                            try:
                                if is_network_template:
                                    await fetch_template_data(dashboard, network_id, org_id, check, network_data)
                                else:
                                    await fetch_data(dashboard, network_id, org_id, check, network_data)
                            except Exception as e:
                                logging.error(f"Error in network MX check {check} for {network_id}: {e}")
                        
                        # MS checks
                        for check in ms_checks:
                            try:
                                if is_network_template:
                                    await fetch_template_data(dashboard, network_id, org_id, check, network_data)
                                else:
                                    await fetch_data(dashboard, network_id, org_id, check, network_data)
                            except Exception as e:
                                logging.error(f"Error in network MS check {check} for {network_id}: {e}")
                        
                        # MR checks
                        for check in mr_checks:
                            try:
                                if is_network_template:
                                    if check in ['getNetworkWirelessSsidFirewallL3FirewallRules', 
                                               'getNetworkWirelessSsidFirewallL7FirewallRules',
                                               'getNetworkWirelessSsidTrafficShapingRules',
                                               'getNetworkWirelessSsidIdentityPsks']:
                                        # Skip SSID-specific checks for templates
                                        logging.debug(f"Skipping SSID-specific check {check} for template")
                                        continue
                                    await fetch_template_data(dashboard, network_id, org_id, check, network_data)
                                else:
                                    if check in ['getNetworkWirelessSsidFirewallL3FirewallRules', 
                                               'getNetworkWirelessSsidFirewallL7FirewallRules',
                                               'getNetworkWirelessSsidTrafficShapingRules',
                                               'getNetworkWirelessSsidIdentityPsks']:
                                        await fetch_ssid_specific_data(dashboard, network_id, check, network_data)
                                    else:
                                        await fetch_data(dashboard, network_id, org_id, check, network_data)
                            except Exception as e:
                                logging.error(f"Error in network MR check {check} for {network_id}: {e}")

                        # Save network data
                        save_to_json(network_directory, 'network_data.json', network_data)
                        save_to_csv(network_directory, 'network_data.csv', network_data)
                        logging.debug(f"Network data saved for network {network_id}")
                    except Exception as e:
                        logging.error(f"Error processing network {network_id}: {e}")
            except Exception as e:
                logging.error(f"Error processing organization {org_id}: {e}")

    # Save session data to JSON
    session_data = {
        'api_key': api_key,
        'orgs': orgs,
        'org_names': org_names,
        'mx_checks': mx_checks,
        'ms_checks': ms_checks,
        'mr_checks': mr_checks,
        'golden_images': golden_images,
        'compliance_networks': compliance_networks,
        'template_ids': template_ids,
        'l3_firewall_source_octet': l3_firewall_source_octet,
        'l3_firewall_destination_octet': l3_firewall_destination_octet,
        'cellular_firewall_source_octet': cellular_firewall_source_octet,
        'cellular_firewall_destination_octet': cellular_firewall_destination_octet,
        'one_to_many_nat_lan_ip_octet': one_to_many_nat_lan_ip_octet,
        'one_to_one_nat_lan_ip_octet': one_to_one_nat_lan_ip_octet,
        'inbound_firewall_source_octet': inbound_firewall_source_octet,
        'inbound_firewall_destination_octet': inbound_firewall_destination_octet,
        'port_forwarding_lan_ip_octet': port_forwarding_lan_ip_octet,
        'vlans_subnet_octet': vlans_subnet_octet,
        'network_product_types': network_product_types,
        'golden_product_types': golden_product_types if 'golden_product_types' in locals() else {'has_mx': True, 'has_ms': True, 'has_mr': True}
    }
    save_to_json('.', 'session_data.json', session_data)
    logging.debug("Session data saved to session_data.json")

def run_gatherinfo(api_key, orgs, mx_checks, ms_checks, mr_checks, golden_images, compliance_networks, 
                  l3_firewall_source_octet, l3_firewall_destination_octet, 
                  cellular_firewall_source_octet, cellular_firewall_destination_octet, 
                  one_to_many_nat_lan_ip_octet, one_to_one_nat_lan_ip_octet, 
                  inbound_firewall_source_octet, inbound_firewall_destination_octet, 
                  port_forwarding_lan_ip_octet, vlans_subnet_octet, template_ids=None, retries=3):
    """
    Wrapper function to run gatherinfo with retry logic
    """
    if template_ids is None:
        template_ids = []
        
    for attempt in range(retries):
        try:
            print_colored(f"Gathering Meraki configuration data (attempt {attempt + 1}/{retries})...", "purple")
            asyncio.run(gatherinfo(
                api_key, orgs, mx_checks, ms_checks, mr_checks, golden_images, compliance_networks,
                l3_firewall_source_octet, l3_firewall_destination_octet,
                cellular_firewall_source_octet, cellular_firewall_destination_octet,
                one_to_many_nat_lan_ip_octet, one_to_one_nat_lan_ip_octet,
                inbound_firewall_source_octet, inbound_firewall_destination_octet,
                port_forwarding_lan_ip_octet, vlans_subnet_octet, template_ids
            ))
            print_colored("Data gathering completed successfully!", "green")
            break  # Exit the loop if gatherinfo succeeds
        except Exception as e:
            logging.error(f"Attempt {attempt + 1} failed: {e}")
            if attempt == retries - 1:
                print_colored("All attempts to gather information have failed. Check logs for details.", "red")
                logging.error("All attempts to gather info have failed.")
