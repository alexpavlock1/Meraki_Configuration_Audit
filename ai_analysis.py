#!/usr/bin/env python3
"""
AI Analysis Module for Meraki Configuration Compliance Tool

This module provides enhanced AI-driven analysis capabilities:
1. Advanced anomaly detection with domain-specific knowledge about Meraki configurations
2. Smart compliance recommendations for fixing non-compliant configurations

Designed to work with the existing compliance_check.py workflow.
"""

import json
import logging
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

#################################################################
#              ENHANCED ANOMALY DETECTION FUNCTIONS             #
#################################################################
def format_check_name(check_key):
    """Convert API check names to readable format"""
    # First, add spaces before capitals and normalize the case
    name = ''
    for char in check_key:
        if char.isupper():
            name += ' ' + char
        else:
            name += char
    
    # Split by known separators
    words = name.replace('_', ' ').split()
    
    # Capitalize each word
    words = [word.capitalize() for word in words]
    
    # Join words with spaces
    return ' '.join(words)

def detect_meraki_anomalies(configs, org_names=None, network_names=None):
    """
    Enhanced anomaly detection incorporating domain knowledge about Meraki security configurations.
    
    Args:
        configs: Dictionary of network configurations {network_id: config_dict}
        org_names: Optional dictionary mapping network IDs to organization names
        network_names: Optional dictionary mapping network IDs to network names
        
    Returns:
        Dictionary of anomalies with security explanations
    """
    if not configs:
        logging.warning("No configurations provided for anomaly detection")
        return {}
    
    # Extract domain-specific security features
    feature_data = []
    network_ids = []
    
    for network_id, config in configs.items():
        features = extract_security_features(config)
        # Only add networks with meaningful features
        if any(value > 0 for value in features.values()):
            feature_data.append(features)
            network_ids.append(network_id)
    
    # Convert to DataFrame
    feature_df = pd.DataFrame(feature_data)
    
    if len(feature_df) < 2 or feature_df.empty:
        logging.warning("Insufficient data for anomaly detection")
        # Instead of returning empty, create a basic security assessment
        return generate_basic_security_assessment(configs, org_names, network_names)
    
    # Fill missing values
    feature_df = feature_df.fillna(0)
    
    # Apply security-based weighting (critical security features weighted higher)
    weights = {
        'has_default_deny': 3.0,
        'has_any_any_allow': 3.0,
        'has_open_ssid': 2.5,
        'content_filtering_enabled': 2.0,
        'incomplete_firewall': 2.0,
        'num_firewall_rules': 1.0,
        'has_port_forwarding': 1.5,
        'has_one_to_one_nat': 1.5,
        'vpn_configured': 1.0
    }
    
    weighted_features = feature_df.copy()
    for feature, weight in weights.items():
        if feature in weighted_features.columns:
            weighted_features[feature] = weighted_features[feature] * weight
    
    # Only proceed if we have meaningful features
    if weighted_features.shape[1] < 2:
        logging.warning("Not enough features for anomaly detection")
        return {}
    
    # Run anomaly detection on weighted features
    try:
        model = IsolationForest(contamination=0.1, random_state=42)
        anomaly_predictions = model.fit_predict(weighted_features)
        anomaly_scores = model.decision_function(weighted_features)
        weighted_features['anomaly'] = anomaly_predictions
        weighted_features['anomaly_score'] = anomaly_scores
        
        # Select anomalies
        anomalies_df = weighted_features[weighted_features['anomaly'] == -1]
        
        # Build results
        anomaly_results = {}
        
        for idx, row in anomalies_df.iterrows():
            if idx >= len(network_ids):
                continue
                
            network_id = network_ids[idx]
            network_config = configs[network_id]
            
            # Get network and org names if available
            org_name = org_names.get(network_id, "Unknown Org") if org_names else "Unknown Org"
            network_name = network_names.get(network_id, network_id) if network_names else network_id
            
            # Generate security explanation
            security_issues = generate_security_explanation(row, feature_df.iloc[idx], network_config)
            anomaly_score = -round(float(row['anomaly_score']), 3)  # Convert to positive risk score
            
            anomaly_results[network_id] = {
                'org_name': org_name,
                'network_name': network_name,
                'anomaly_score': anomaly_score,
                'risk_level': determine_risk_level(anomaly_score),
                'security_issues': security_issues
            }
        
        return anomaly_results
        
    except Exception as e:
        logging.error(f"Error in anomaly detection: {e}")
        return {}

def extract_security_features(config):
    """Extract security-relevant features from a network configuration."""
    features = {}
    
    # Firewall features
    if 'firewalll3firewallrules' in config:
        rules = config.get('firewalll3firewallrules', {})
        if isinstance(rules, dict):
            rules = rules.get('rules', [])
        else:
            rules = []
            
        features['num_firewall_rules'] = len(rules)
        features['has_default_deny'] = 0
        features['has_any_any_allow'] = 0
        features['incomplete_firewall'] = 0
        
        # Look for key firewall patterns
        if rules:
            for rule in rules:
                # Check for critical security patterns
                if rule.get('policy') == 'deny' and rule.get('srcCidr') == 'Any' and rule.get('destCidr') == 'Any':
                    features['has_default_deny'] = 1
                if rule.get('policy') == 'allow' and rule.get('srcCidr') == 'Any' and rule.get('destCidr') == 'Any':
                    features['has_any_any_allow'] = 1
        else:
            features['incomplete_firewall'] = 1
    else:
        features['incomplete_firewall'] = 1
        
    # Content filtering
    if 'contentfiltering' in config:
        cf = config.get('contentfiltering', {})
        if isinstance(cf, dict):
            features['content_filtering_enabled'] = 1 if cf.get('blockedUrlCategories') else 0
        else:
            features['content_filtering_enabled'] = 0
    else:
        features['content_filtering_enabled'] = 0
        
    # Wireless security
    if 'wirelessssids' in config:
        ssids = config.get('wirelessssids', [])
        features['has_open_ssid'] = 0
        if isinstance(ssids, list):
            for ssid in ssids:
                if ssid.get('enabled') and ssid.get('authMode') == 'open':
                    features['has_open_ssid'] = 1
    
    # NAT rules
    features['has_port_forwarding'] = 1 if 'firewallportforward' in config else 0
    features['has_one_to_one_nat'] = 1 if 'firewallonetonatone' in config else 0
    
    # VPN configuration
    features['vpn_configured'] = 1 if 'vpnsitetosite' in config else 0
    
    return features

def generate_security_explanation(anomaly_row, feature_row, config):
    """Generate security-focused explanation for why this network is anomalous."""
    issues = []
    
    # Firewall issues
    if 'has_default_deny' in feature_row and feature_row['has_default_deny'] == 0:
        issues.append({
            'category': 'Firewall',
            'severity': 'High',
            'description': "Missing default deny firewall rule (security best practice)",
            'recommendation': "Add a bottom rule with policy 'deny', source 'Any', destination 'Any' to block traffic not explicitly allowed."
        })
        
    if 'has_any_any_allow' in feature_row and feature_row['has_any_any_allow'] == 1:
        issues.append({
            'category': 'Firewall',
            'severity': 'Critical',
            'description': "Has 'any-to-any allow' firewall rule (significant security risk)",
            'recommendation': "Replace broad 'any' rules with specific source/destination rules for required traffic only."
        })
    
    if 'incomplete_firewall' in feature_row and feature_row['incomplete_firewall'] == 1:
        issues.append({
            'category': 'Firewall',
            'severity': 'High',
            'description': "Incomplete or missing firewall configuration",
            'recommendation': "Configure proper L3 firewall rules to restrict traffic flows."
        })
    
    # Wireless issues
    if 'has_open_ssid' in feature_row and feature_row['has_open_ssid'] == 1:
        issues.append({
            'category': 'Wireless',
            'severity': 'High',
            'description': "Open wireless network without authentication",
            'recommendation': "Change authentication to WPA2/WPA3 with strong PSK or enterprise authentication."
        })
    
    # Content filtering
    if 'content_filtering_enabled' in feature_row and feature_row['content_filtering_enabled'] == 0:
        issues.append({
            'category': 'Content Filtering',
            'severity': 'Medium',
            'description': "Content filtering not enabled",
            'recommendation': "Enable content filtering to block malicious or unwanted categories."
        })
    
    # NAT and Port Forwarding
    nat_and_port = feature_row.get('has_port_forwarding', 0) + feature_row.get('has_one_to_one_nat', 0)
    if nat_and_port > 1:
        issues.append({
            'category': 'NAT',
            'severity': 'Low',
            'description': "Multiple NAT configurations may increase attack surface",
            'recommendation': "Review NAT and port forwarding rules to ensure they expose only necessary services."
        })
    
    return issues

def extract_non_compliant_data(network_verdicts, verdict_table, check_name_mapping, network_names, compliance_networks):
    """Parse the non-compliant networks from verdict data structure"""
    results = {}
    
    for (org_name, network_name), verdict in network_verdicts.items():
        if verdict == "Non-Compliant":
            # Find network ID
            network_id = next((nid for nid, name in network_names.items() if name == network_name), None)
            if network_id:
                non_compliant_checks = []
                # Find which checks failed
                for row in verdict_table._rows:
                    if row[0] == org_name and row[1] == network_name and "Non-Compliant" in row[3]:
                        check_display_name = row[2]
                        # Try to find the API check name that matches this display name
                        check = None
                        for api_name, display_name in check_name_mapping.items():
                            if display_name == check_display_name:
                                check = api_name
                                break
                        
                        if check:
                            non_compliant_checks.append(check)
                        else:
                            logging.warning(f"Could not map display name '{check_display_name}' to API check name")
                
                # Map network to org
                org_id = None
                for o_id, nets in compliance_networks.items():
                    if network_id in nets:
                        org_id = o_id
                        break
                
                if org_id and non_compliant_checks:
                    results[network_id] = {
                        'network_info': {org_id: [network_id]},
                        'non_compliant_checks': non_compliant_checks
                    }
                    logging.debug(f"Added non-compliant network {network_id} with {len(non_compliant_checks)} failed checks")
    
    logging.debug(f"Extracted {len(results)} non-compliant networks")
    return results

def generate_basic_security_assessment(configs, org_names=None, network_names=None, golden_images=None, compliance_networks=None):
    """Generate basic security assessment when ML-based detection isn't possible"""
    anomaly_results = {}
    
    for network_id, config in configs.items():
        # Skip golden image configurations
        if golden_images and network_id in golden_images.values():
            continue
            
        network_name = network_names.get(network_id, network_id) if network_names else network_id
        org_name = "Unknown Org"
        
        if org_names and compliance_networks:
            for org_id, networks in compliance_networks.items():
                if network_id in networks:
                    org_name = org_names.get(org_id, "Unknown Org")
                    break
        
        # Perform simple security checks
        security_issues = []
        
        # Check firewall rules
        if 'firewalll3firewallrules' in config:
            rules = config.get('firewalll3firewallrules', {})
            has_default_deny = False
            has_any_any_allow = False
            
            if isinstance(rules, dict) and 'rules' in rules:
                for rule in rules['rules']:
                    if rule.get('policy') == 'deny' and rule.get('srcCidr') == 'Any' and rule.get('destCidr') == 'Any':
                        has_default_deny = True
                    if rule.get('policy') == 'allow' and rule.get('srcCidr') == 'Any' and rule.get('destCidr') == 'Any':
                        has_any_any_allow = True
            
            if not has_default_deny:
                security_issues.append({
                    'category': 'Firewall',
                    'severity': 'High',
                    'description': "Missing default deny firewall rule (security best practice)",
                    'recommendation': "Add a bottom rule with policy 'deny', source 'Any', destination 'Any'"
                })
            
            if has_any_any_allow:
                security_issues.append({
                    'category': 'Firewall',
                    'severity': 'Critical',
                    'description': "Has 'any-to-any allow' firewall rule (significant security risk)",
                    'recommendation': "Replace broad 'any' rules with specific rules"
                })
        
        # Add security issue if no security features detected
        if not security_issues:
            security_issues.append({
                'category': 'General',
                'severity': 'Low',
                'description': "Basic configuration detected",
                'recommendation': "Consider enabling additional security features"
            })
        
        # Only add networks with security issues
        if security_issues:
            anomaly_results[network_id] = {
                'org_name': org_name,
                'network_name': network_name,
                'anomaly_score': 0.5,  # Medium score for manual assessment
                'risk_level': "Low",
                'security_issues': security_issues
            }
    
    return anomaly_results

def determine_risk_level(anomaly_score):
    """Convert anomaly score to a risk level label."""
    if anomaly_score > 0.8:
        return "Critical"
    elif anomaly_score > 0.6:
        return "High"
    elif anomaly_score > 0.4:
        return "Medium"
    else:
        return "Low"

#################################################################
#             SMART COMPLIANCE RECOMMENDATIONS                  #
#################################################################

def generate_compliance_recommendations(golden_configs, network_configs, non_compliant_results):
    """
    Generate detailed and actionable compliance recommendations
    with enhanced context, detailed steps, and impact information.
    """
    recommendations = {}
    
    for network_id, checks in non_compliant_results.items():
        network_recommendations = []
        
        # Find which organization this network belongs to
        org_id = None
        for org, networks in checks.get('network_info', {}).items():
            if network_id in networks:
                org_id = org
                break
        
        if not org_id:
            continue
            
        # Get the configurations
        golden_config = golden_configs.get(org_id, {})
        network_config = network_configs.get(network_id, {})
        
        # Process each non-compliant check
        non_compliant_checks = checks.get('non_compliant_checks', [])
        for check in non_compliant_checks:
            check_name = check.replace('getNetwork', '').replace('getOrganization', '').replace('Appliance', '').replace('Switch', '').lower()
            
            # Get the configs for this check
            golden_check_config = golden_config.get(check_name)
            network_check_config = network_config.get(check_name)
            
            # Skip if either config is missing
            if not golden_check_config or not network_check_config:
                continue
            
            # Generate recommendations based on configuration type
            if 'firewalll3firewallrules' in check_name:
                recommendation = recommend_firewall_fixes(golden_check_config, network_check_config, check_name)
                if recommendation:
                    network_recommendations.append(recommendation)
                    
            elif 'contentfiltering' in check_name:
                recommendation = recommend_content_filtering_fixes(golden_check_config, network_check_config)
                if recommendation:
                    network_recommendations.append(recommendation)
                    
            elif 'vlans' in check_name:
                recommendation = recommend_vlan_fixes(golden_check_config, network_check_config)
                if recommendation:
                    network_recommendations.append(recommendation)
            
            elif 'wirelessssids' in check_name:
                recommendation = recommend_wireless_fixes(golden_check_config, network_check_config)
                if recommendation:
                    network_recommendations.append(recommendation)
                    
            elif 'securityintrusion' in check_name:
                recommendation = recommend_security_intrusion_fixes(golden_check_config, network_check_config)
                if recommendation:
                    network_recommendations.append(recommendation)
                    
            elif 'securitymalware' in check_name:
                recommendation = recommend_security_malware_fixes(golden_check_config, network_check_config)
                if recommendation:
                    network_recommendations.append(recommendation)
                    
            elif 'staticroutes' in check_name:
                recommendation = recommend_static_routes_fixes(golden_check_config, network_check_config)
                if recommendation:
                    network_recommendations.append(recommendation)
                    
            elif 'trafficshaping' in check_name:
                recommendation = recommend_traffic_shaping_fixes(golden_check_config, network_check_config)
                if recommendation:
                    network_recommendations.append(recommendation)
                    
            elif 'vpnsitetosite' in check_name:
                recommendation = recommend_vpn_fixes(golden_check_config, network_check_config)
                if recommendation:
                    network_recommendations.append(recommendation)
            
            # Default recommendation for other check types
            else:
                recommendation = generate_generic_recommendation(check_name, golden_check_config, network_check_config)
                if recommendation:
                    network_recommendations.append(recommendation)
        
        if network_recommendations:
            recommendations[network_id] = network_recommendations
            
    # If no specific recommendations were generated but we have non-compliant networks,
    # generate enhanced generic recommendations       
    if not recommendations and non_compliant_results:
        for network_id, checks in non_compliant_results.items():
            generic_recommendations = []
            for check in checks.get('non_compliant_checks', []):
                generic_recommendations.append(generate_generic_recommendation(check, None, None))
            if generic_recommendations:
                recommendations[network_id] = generic_recommendations
    
    return recommendations

def recommend_firewall_fixes(golden_config, network_config, check_name):
    """Generate detailed recommendations for fixing firewall issues with exact differences and impact assessment."""
    # Extract rules from either dictionary format or direct list
    if isinstance(golden_config, dict) and 'rules' in golden_config:
        golden_rules = golden_config.get('rules', [])
    else:
        golden_rules = golden_config if isinstance(golden_config, list) else []
        
    if isinstance(network_config, dict) and 'rules' in network_config:
        network_rules = network_config.get('rules', [])
    else:
        network_rules = network_config if isinstance(network_config, list) else []
    
    # Find missing security rules
    missing_rules = []
    for golden_rule in golden_rules:
        if not any(are_rules_equivalent(golden_rule, network_rule) for network_rule in network_rules):
            missing_rules.append(golden_rule)
    
    # Find extra rules that don't exist in golden image
    extra_rules = []
    for network_rule in network_rules:
        if not any(are_rules_equivalent(network_rule, golden_rule) for golden_rule in golden_rules):
            extra_rules.append(network_rule)
    
    # Find problematic rules with specific security concerns
    problematic_rules = []
    for network_rule in network_rules:
        # Check for "any-to-any" allow rules
        if network_rule.get('policy') == 'allow' and network_rule.get('srcCidr') == 'Any' and network_rule.get('destCidr') == 'Any':
            problematic_rules.append({
                'rule': network_rule,
                'issue': 'Overly permissive "any-to-any" allow rule creates security risk',
                'impact': 'This rule allows all traffic between any source and destination, effectively bypassing firewall protection',
                'severity': 'Critical'
            })
        # Check for rules that might expose sensitive services
        elif network_rule.get('policy') == 'allow' and network_rule.get('destPort') in ['22', '3389', '445', '1433', '3306', '5432']:
            problematic_rules.append({
                'rule': network_rule,
                'issue': f'Rule allows access to potentially sensitive port {network_rule.get("destPort")}',
                'impact': 'This may expose administrative or database services to unauthorized access',
                'severity': 'High'
            })
    
    if not missing_rules and not problematic_rules and not extra_rules:
        return None
        
    # Create recommendation with enhanced details
    recommendation = {
        'category': 'Firewall',
        'title': format_check_name(check_name),
        'overview': f"The firewall configuration doesn't match the golden image standard. Firewalls control traffic flow in your network and are critical for security.",
        'actions': []
    }
        
    # Generate actionable advice with detailed steps
    if missing_rules:
        action = {
            'action_type': 'Add Missing Rules',
            'description': f"Add {len(missing_rules)} missing security rules to match golden configuration",
            'impact': 'Missing firewall rules may leave network segments vulnerable to unauthorized access or attacks',
            'severity': 'High',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Firewall in your Meraki dashboard',
                '2. Scroll to the L3 Firewall Rules section',
                '3. Add the following rules in the specified order:',
            ],
            'details': []
        }
        
        # Add each rule with detailed formatting
        for i, rule in enumerate(missing_rules):
            rule_details = format_rule_for_display(rule)
            rule_impact = get_rule_impact(rule)
            action['details'].append(f"Rule #{i+1}: {rule_details}")
            if rule_impact:
                action['details'].append(f"   - Purpose: {rule_impact}")
                
        recommendation['actions'].append(action)
    
    if problematic_rules:
        action = {
            'action_type': 'Fix Security Risks',
            'description': f"Modify {len(problematic_rules)} problematic rules that pose security risks",
            'impact': 'These rules create significant security vulnerabilities in your network',
            'severity': 'Critical',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Firewall in your Meraki dashboard',
                '2. Locate and modify the following rules:',
            ],
            'details': []
        }
        
        for i, item in enumerate(problematic_rules):
            rule = item['rule']
            rule_details = format_rule_for_display(rule)
            action['details'].append(f"Rule #{i+1}: {rule_details}")
            action['details'].append(f"   - Issue: {item['issue']} ({item['severity']})")
            action['details'].append(f"   - Impact: {item['impact']}")
            action['details'].append(f"   - Recommendation: Replace with more specific rules that limit access only to necessary sources/destinations/services")
                
        recommendation['actions'].append(action)
        
    if extra_rules:
        action = {
            'action_type': 'Review Extra Rules',
            'description': f"Review {len(extra_rules)} rules that don't exist in the golden image",
            'impact': 'Extra rules may create unintended access paths or bypass security controls defined in the golden image',
            'severity': 'Medium',
            'implementation_steps': [
                '1. Review each extra rule to determine if it\'s necessary for this specific network',
                '2. If not needed, navigate to Security & SD-WAN > Configure > Firewall and remove the following rules:',
            ],
            'details': []
        }
        
        for i, rule in enumerate(extra_rules):
            rule_details = format_rule_for_display(rule)
            action['details'].append(f"Rule #{i+1}: {rule_details}")
                
        recommendation['actions'].append(action)
    
    return recommendation

def recommend_content_filtering_fixes(golden_config, network_config):
    """Generate detailed recommendations for fixing content filtering issues with specific category information."""
    # Handle different possible formats
    if isinstance(golden_config, dict):
        golden_categories = set(cat.get('id') for cat in golden_config.get('blockedUrlCategories', []))
        golden_allowed_urls = set(golden_config.get('allowedUrlPatterns', []))
        golden_blocked_urls = set(golden_config.get('blockedUrlPatterns', []))
    else:
        return None
        
    if isinstance(network_config, dict):
        network_categories = set(cat.get('id') for cat in network_config.get('blockedUrlCategories', []))
        network_allowed_urls = set(network_config.get('allowedUrlPatterns', []))
        network_blocked_urls = set(network_config.get('blockedUrlPatterns', []))
    else:
        return None
    
    # Find differences
    missing_categories = golden_categories - network_categories
    extra_categories = network_categories - golden_categories
    missing_allowed_urls = golden_allowed_urls - network_allowed_urls
    missing_blocked_urls = golden_blocked_urls - network_blocked_urls
    
    if not any([missing_categories, extra_categories, missing_allowed_urls, missing_blocked_urls]):
        return None
    
    # Create recommendation with enhanced context
    recommendation = {
        'category': 'Content Filtering',
        'title': 'Content Filtering Configuration',
        'overview': "Content filtering protects your network by controlling access to websites based on categories and specific URLs. Maintaining consistent content filtering across your organization is important for security policy enforcement.",
        'actions': []
    }
    
    # Generate actionable advice with detailed steps and explanations
    if missing_categories:
        category_descriptions = get_content_filtering_category_descriptions(missing_categories)
        
        action = {
            'action_type': 'Add Missing Blocked Categories',
            'description': f"Block {len(missing_categories)} missing categories that are blocked in golden image",
            'impact': 'Missing blocked categories may allow users to access prohibited content types defined in your security policy',
            'severity': 'Medium',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Content filtering in your Meraki dashboard',
                '2. Under "Blocked URL categories", click "Edit"',
                '3. Check the following categories to block:',
            ],
            'details': []
        }
        
        for category in missing_categories:
            category_desc = category_descriptions.get(category, "")
            if category_desc:
                action['details'].append(f"{category}: {category_desc}")
            else:
                action['details'].append(f"{category}")
                
        recommendation['actions'].append(action)
    
    if missing_allowed_urls:
        action = {
            'action_type': 'Add Allowed URL Patterns',
            'description': "Add missing allowed URL patterns to match golden configuration",
            'impact': 'Users may be unable to access legitimate websites that should be exempted from category blocks',
            'severity': 'Medium',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Content filtering in your Meraki dashboard',
                '2. Under "Allowed URLs", click "Edit"',
                '3. Add the following URL patterns:',
            ],
            'details': list(missing_allowed_urls)
        }
        recommendation['actions'].append(action)
    
    if missing_blocked_urls:
        action = {
            'action_type': 'Add Blocked URL Patterns',
            'description': "Add missing blocked URL patterns to match golden configuration",
            'impact': 'Specific high-risk websites may remain accessible despite category filtering',
            'severity': 'Medium to High',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Content filtering in your Meraki dashboard',
                '2. Under "Blocked URLs", click "Edit"',
                '3. Add the following URL patterns:',
            ],
            'details': list(missing_blocked_urls)
        }
        recommendation['actions'].append(action)
    
    if extra_categories:
        action = {
            'action_type': 'Review Extra Blocked Categories',
            'description': f"Review {len(extra_categories)} categories blocked in this network but not in golden image",
            'impact': 'Over-blocking may unnecessarily restrict user access to legitimate resources',
            'severity': 'Low',
            'implementation_steps': [
                '1. Review these extra blocked categories to determine if they should remain blocked',
                '2. If they should be unblocked to match the standard, navigate to Security & SD-WAN > Configure > Content filtering',
                '3. Under "Blocked URL categories", click "Edit" and uncheck these categories:',
            ],
            'details': list(extra_categories)
        }
        recommendation['actions'].append(action)
    
    return recommendation

def recommend_vlan_fixes(golden_config, network_config):
    """Generate detailed recommendations for fixing VLAN issues with subnet information and implementation steps."""
    # Handle different possible formats
    if isinstance(golden_config, list):
        golden_vlans = {vlan.get('id'): vlan for vlan in golden_config if isinstance(vlan, dict)}
    elif isinstance(golden_config, dict):
        golden_vlans = golden_config
    else:
        return None
        
    if isinstance(network_config, list):
        network_vlans = {vlan.get('id'): vlan for vlan in network_config if isinstance(vlan, dict)}
    elif isinstance(network_config, dict):
        network_vlans = network_config
    else:
        return None
    
    # Find differences
    missing_vlans = set(golden_vlans.keys()) - set(network_vlans.keys())
    common_vlans = set(golden_vlans.keys()) & set(network_vlans.keys())
    
    # Check for misconfigured common VLANs
    misconfigured_vlans = []
    for vlan_id in common_vlans:
        golden_vlan = golden_vlans[vlan_id]
        network_vlan = network_vlans[vlan_id]
        
        # Check for key differences with detailed tracking
        differences = []
        for key in ['name', 'subnet', 'applianceIp', 'dhcpHandling', 'dhcpLeaseTime', 'dnsNameservers']:
            if key in golden_vlan and key in network_vlan and golden_vlan[key] != network_vlan[key]:
                differences.append({
                    'property': key,
                    'golden_value': golden_vlan[key],
                    'network_value': network_vlan[key],
                    'impact': get_vlan_property_impact(key)
                })
        
        # Check DHCP settings differences
        if 'dhcpOptions' in golden_vlan and 'dhcpOptions' in network_vlan:
            golden_dhcp = golden_vlan['dhcpOptions']
            network_dhcp = network_vlan['dhcpOptions']
            
            for option in golden_dhcp:
                if option not in network_dhcp:
                    differences.append({
                        'property': f'dhcpOption_{option["code"]}',
                        'golden_value': f'Code: {option["code"]}, Value: {option["value"]}',
                        'network_value': 'Missing',
                        'impact': 'Missing DHCP option may affect client network functionality'
                    })
        
        if differences:
            misconfigured_vlans.append({
                'vlan_id': vlan_id,
                'vlan_name': golden_vlan.get('name', f'VLAN {vlan_id}'),
                'differences': differences
            })
    
    if not missing_vlans and not misconfigured_vlans:
        return None
    
    # Create recommendation with enhanced details
    recommendation = {
        'category': 'VLANs',
        'title': 'VLAN Configuration',
        'overview': "VLANs (Virtual LANs) segment your network and control traffic flow between different network segments. Proper VLAN configuration is critical for both security and network performance.",
        'actions': []
    }
    
    # Generate actionable advice for missing VLANs
    if missing_vlans:
        action = {
            'action_type': 'Add Missing VLANs',
            'description': f"Add {len(missing_vlans)} missing VLANs to match golden configuration",
            'impact': 'Missing VLANs may result in improper network segmentation and security gaps',
            'severity': 'High',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Addressing & VLANs in your Meraki dashboard',
                '2. Click "Add VLAN" for each missing VLAN and configure with these settings:',
            ],
            'details': []
        }
        
        for vlan_id in missing_vlans:
            vlan = golden_vlans[vlan_id]
            vlan_details = []
            vlan_details.append(f"VLAN {vlan_id}: {vlan.get('name', 'Unnamed')}")
            vlan_details.append(f"   - Subnet: {vlan.get('subnet', 'Not specified')}")
            vlan_details.append(f"   - Appliance IP: {vlan.get('applianceIp', 'Not specified')}")
            
            dhcp_handling = vlan.get('dhcpHandling', 'None')
            if dhcp_handling == 'Run a DHCP server':
                vlan_details.append(f"   - DHCP: Enabled with lease time {vlan.get('dhcpLeaseTime', 'default')}")
                if 'dhcpOptions' in vlan:
                    for option in vlan['dhcpOptions']:
                        vlan_details.append(f"      - DHCP Option {option['code']}: {option['value']}")
            elif dhcp_handling == 'Relay DHCP to another server':
                vlan_details.append(f"   - DHCP: Relay to {vlan.get('dhcpRelayServerIps', 'Not specified')}")
            else:
                vlan_details.append(f"   - DHCP: Disabled")
                
            action['details'].extend(vlan_details)
            
        recommendation['actions'].append(action)
    
    # Generate advice for misconfigured VLANs
    if misconfigured_vlans:
        action = {
            'action_type': 'Fix Misconfigured VLANs',
            'description': f"Correct configuration on {len(misconfigured_vlans)} existing VLANs",
            'impact': 'Misconfigured VLANs may cause network connectivity issues, security gaps, or IP conflicts',
            'severity': 'Medium',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Addressing & VLANs in your Meraki dashboard',
                '2. Click on each VLAN below and update with these changes:',
            ],
            'details': []
        }
        
        for m in misconfigured_vlans:
            vlan_id = m['vlan_id']
            vlan_name = m['vlan_name']
            action['details'].append(f"VLAN {vlan_id}: {vlan_name}")
            
            for diff in m['differences']:
                action['details'].append(f"   - Update {diff['property']}")
                action['details'].append(f"     From: {diff['network_value']}")
                action['details'].append(f"     To: {diff['golden_value']}")
                if 'impact' in diff:
                    action['details'].append(f"     Impact: {diff['impact']}")
                
        recommendation['actions'].append(action)
    
    return recommendation

def recommend_wireless_fixes(golden_config, network_config):
    """Generate enhanced recommendations for fixing wireless SSID issues with security impact and best practices."""
    # Extract and normalize SSIDs
    if isinstance(golden_config, list):
        golden_ssids = {ssid.get('number'): ssid for ssid in golden_config if isinstance(ssid, dict)}
    else:
        return None
        
    if isinstance(network_config, list):
        network_ssids = {ssid.get('number'): ssid for ssid in network_config if isinstance(ssid, dict)}
    else:
        return None
    
    # Find enabled SSIDs in golden config
    enabled_golden_ssids = {num: ssid for num, ssid in golden_ssids.items() if ssid.get('enabled')}
    
    # Look for mismatches
    missing_ssids = []
    misconfigured_ssids = []
    
    for num, golden_ssid in enabled_golden_ssids.items():
        # Check if SSID exists and is enabled
        if num not in network_ssids:
            missing_ssids.append(golden_ssid)
            continue
            
        network_ssid = network_ssids[num]
        if not network_ssid.get('enabled', False):
            missing_ssids.append(golden_ssid)
            continue
        
        # Check for security misconfigurations with detailed tracking
        differences = []
        # Basic settings
        for key in ['name', 'visible']:
            if key in golden_ssid and key in network_ssid and golden_ssid[key] != network_ssid[key]:
                differences.append({
                    'property': key,
                    'golden_value': golden_ssid[key],
                    'network_value': network_ssid[key],
                    'impact': get_ssid_property_impact(key)
                })
        
        # Security settings - these have security implications
        for key in ['authMode', 'encryptionMode', 'wpaEncryptionMode', 'ipAssignmentMode', 'minBitrate', 'bandSelection']:
            if key in golden_ssid and key in network_ssid and golden_ssid[key] != network_ssid[key]:
                differences.append({
                    'property': key,
                    'golden_value': golden_ssid[key],
                    'network_value': network_ssid[key],
                    'impact': get_ssid_property_impact(key),
                    'severity': get_ssid_severity(key, golden_ssid[key], network_ssid[key])
                })
        
        # Check for downgrade in security
        if (network_ssid.get('authMode') == 'open' and golden_ssid.get('authMode') != 'open') or \
           (network_ssid.get('encryptionMode') == 'wep' and golden_ssid.get('encryptionMode') != 'wep') or \
           (network_ssid.get('wpaEncryptionMode') == 'WPA1' and golden_ssid.get('wpaEncryptionMode') != 'WPA1'):
            differences.append({
                'property': 'security_downgrade',
                'golden_value': f"AuthMode: {golden_ssid.get('authMode')}, Encryption: {golden_ssid.get('encryptionMode')}, WPA: {golden_ssid.get('wpaEncryptionMode')}",
                'network_value': f"AuthMode: {network_ssid.get('authMode')}, Encryption: {network_ssid.get('encryptionMode')}, WPA: {network_ssid.get('wpaEncryptionMode')}",
                'impact': 'Significant security downgrade from golden image standard',
                'severity': 'Critical'
            })
        
        if differences:
            misconfigured_ssids.append({
                'ssid_number': num,
                'ssid_name': golden_ssid.get('name', f'SSID {num}'),
                'differences': differences
            })
    
    if not missing_ssids and not misconfigured_ssids:
        return None
    
    # Create recommendation with enhanced details
    recommendation = {
        'category': 'Wireless',
        'title': 'SSID Configuration',
        'overview': "Wireless SSIDs are the access points through which users connect to your network. Proper configuration is essential for both security and user experience.",
        'actions': []
    }
    
    # Generate actionable advice with best practices
    if missing_ssids:
        action = {
            'action_type': 'Add/Enable Missing SSIDs',
            'description': f"Add or enable {len(missing_ssids)} missing SSIDs to match golden configuration",
            'impact': 'Inconsistent wireless access points may create confusion and gaps in wireless coverage',
            'severity': 'Medium',
            'implementation_steps': [
                '1. Navigate to Wireless > Configure > SSIDs in your Meraki dashboard',
                '2. For each SSID below, click on the corresponding number and configure with these settings:',
            ],
            'details': []
        }
        
        for ssid in missing_ssids:
            ssid_num = ssid.get('number')
            ssid_name = ssid.get('name', f'SSID {ssid_num}')
            
            ssid_details = []
            ssid_details.append(f"SSID {ssid_num}: {ssid_name}")
            ssid_details.append(f"   - Visibility: {'Visible' if ssid.get('visible', True) else 'Hidden'}")
            ssid_details.append(f"   - Authentication: {ssid.get('authMode', 'Open')}")
            
            if ssid.get('authMode') != 'open':
                ssid_details.append(f"   - Encryption: {ssid.get('encryptionMode', 'WPA')} / {ssid.get('wpaEncryptionMode', 'WPA2')}")
            
            action['details'].extend(ssid_details)
            
        recommendation['actions'].append(action)
    
    if misconfigured_ssids:
        action = {
            'action_type': 'Fix Misconfigured SSIDs',
            'description': f"Correct configuration on {len(misconfigured_ssids)} existing SSIDs",
            'impact': 'Misconfigured SSIDs may create security vulnerabilities or affect user connectivity',
            'severity': 'High',
            'implementation_steps': [
                '1. Navigate to Wireless > Configure > SSIDs in your Meraki dashboard',
                '2. Click on each SSID number below and update with these changes:',
            ],
            'details': []
        }
        
        for m in misconfigured_ssids:
            ssid_num = m['ssid_number']
            ssid_name = m['ssid_name']
            action['details'].append(f"SSID {ssid_num}: {ssid_name}")
            
            # Group differences by severity
            critical_diffs = [d for d in m['differences'] if d.get('severity') == 'Critical']
            high_diffs = [d for d in m['differences'] if d.get('severity') == 'High']
            medium_diffs = [d for d in m['differences'] if d.get('severity') == 'Medium']
            low_diffs = [d for d in m['differences'] if d.get('severity') == 'Low' or 'severity' not in d]
            
            # Start with most critical differences
            if critical_diffs:
                action['details'].append(f"   - CRITICAL security issues:")
                for diff in critical_diffs:
                    action['details'].append(f"     * Change {diff['property']} from '{diff['network_value']}' to '{diff['golden_value']}'")
                    if 'impact' in diff:
                        action['details'].append(f"       Impact: {diff['impact']}")
            
            if high_diffs:
                action['details'].append(f"   - HIGH priority changes:")
                for diff in high_diffs:
                    action['details'].append(f"     * Change {diff['property']} from '{diff['network_value']}' to '{diff['golden_value']}'")
                    if 'impact' in diff:
                        action['details'].append(f"       Impact: {diff['impact']}")
                        
            if medium_diffs or low_diffs:
                action['details'].append(f"   - Other changes needed:")
                for diff in medium_diffs + low_diffs:
                    action['details'].append(f"     * Change {diff['property']} from '{diff['network_value']}' to '{diff['golden_value']}'")
                
        recommendation['actions'].append(action)
    
    return recommendation

def recommend_security_intrusion_fixes(golden_config, network_config):
    """Generate detailed recommendations for security intrusion settings."""
    if not isinstance(golden_config, dict) or not isinstance(network_config, dict):
        return None
    
    differences = []
    
    # Compare mode
    if golden_config.get('mode') != network_config.get('mode'):
        differences.append({
            'property': 'mode',
            'golden_value': golden_config.get('mode'),
            'network_value': network_config.get('mode'),
            'impact': 'Intrusion detection/prevention mode affects security protection level',
            'severity': 'High'
        })
    
    # Compare IPS rules if they exist
    golden_rules = golden_config.get('idsRules', [])
    network_rules = network_config.get('idsRules', [])
    
    golden_rule_ids = {rule.get('ruleId') for rule in golden_rules if isinstance(rule, dict)}
    network_rule_ids = {rule.get('ruleId') for rule in network_rules if isinstance(rule, dict)}
    
    missing_rules = golden_rule_ids - network_rule_ids
    extra_rules = network_rule_ids - golden_rule_ids
    
    # Check for rules with different settings
    common_rules = golden_rule_ids.intersection(network_rule_ids)
    for rule_id in common_rules:
        golden_rule = next((r for r in golden_rules if r.get('ruleId') == rule_id), {})
        network_rule = next((r for r in network_rules if r.get('ruleId') == rule_id), {})
        
        if golden_rule.get('enabled') != network_rule.get('enabled'):
            differences.append({
                'property': f'rule_{rule_id}',
                'golden_value': 'Enabled' if golden_rule.get('enabled') else 'Disabled',
                'network_value': 'Enabled' if network_rule.get('enabled') else 'Disabled',
                'impact': 'Different rule enablement may affect security protection',
                'severity': 'Medium'
            })
    
    if not differences and not missing_rules and not extra_rules:
        return None
    
    # Create recommendation
    recommendation = {
        'category': 'Security',
        'title': 'Security Intrusion Settings',
        'overview': "Intrusion Prevention/Detection settings protect your network from malicious traffic and attacks. Proper configuration is vital for network security.",
        'actions': []
    }
    
    # Add action for mode differences
    mode_diffs = [d for d in differences if d['property'] == 'mode']
    if mode_diffs:
        action = {
            'action_type': 'Update IPS/IDS Mode',
            'description': "Update the Intrusion Prevention/Detection mode to match golden configuration",
            'impact': 'Using a less protective mode may leave the network vulnerable to attacks',
            'severity': 'High',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Threat protection in your Meraki dashboard',
                '2. Under "Intrusion prevention", select the correct mode:',
            ],
            'details': []
        }
        
        for diff in mode_diffs:
            golden_mode = diff['golden_value']
            action['details'].append(f"Change mode from '{diff['network_value']}' to '{golden_mode}'")
            
            # Add explanation of the mode
            if golden_mode == 'prevention':
                action['details'].append("   - Prevention mode actively blocks malicious traffic")
            elif golden_mode == 'detection':
                action['details'].append("   - Detection mode logs malicious traffic but doesn't block it")
            elif golden_mode == 'disabled':
                action['details'].append("   - Disabled mode turns off intrusion protection entirely")
                
        recommendation['actions'].append(action)
    
    # Add action for rule differences
    if missing_rules or extra_rules or any(d['property'].startswith('rule_') for d in differences):
        action = {
            'action_type': 'Update IPS/IDS Rules',
            'description': "Update the Intrusion Prevention/Detection rules to match golden configuration",
            'impact': 'Missing or incorrectly configured rules may leave the network vulnerable to specific attack types',
            'severity': 'Medium',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Threat protection in your Meraki dashboard',
                '2. Under "Intrusion prevention", click "Configure" and adjust the following rules:',
            ],
            'details': []
        }
        
        if missing_rules:
            action['details'].append(f"Enable the following missing rules: {', '.join(str(r) for r in missing_rules)}")
        
        for diff in [d for d in differences if d['property'].startswith('rule_')]:
            rule_id = diff['property'].replace('rule_', '')
            action['details'].append(f"Rule {rule_id}: Change from '{diff['network_value']}' to '{diff['golden_value']}'")
            
        if extra_rules:
            action['details'].append(f"Review these extra enabled rules not in golden image: {', '.join(str(r) for r in extra_rules)}")
            
        recommendation['actions'].append(action)
    
    return recommendation

def recommend_security_malware_fixes(golden_config, network_config):
    """Generate detailed recommendations for malware protection settings."""
    if not isinstance(golden_config, dict) or not isinstance(network_config, dict):
        return None
    
    differences = []
    
    # Compare mode
    if golden_config.get('mode') != network_config.get('mode'):
        differences.append({
            'property': 'mode',
            'golden_value': golden_config.get('mode'),
            'network_value': network_config.get('mode'),
            'impact': 'Malware protection mode affects security posture',
            'severity': 'High'
        })
    
    # Compare allowed files if they exist
    golden_allowed = set(golden_config.get('allowedFiles', []))
    network_allowed = set(network_config.get('allowedFiles', []))
    
    missing_allowed = golden_allowed - network_allowed
    extra_allowed = network_allowed - golden_allowed
    
    # Compare allowed URLs if they exist
    golden_urls = set(golden_config.get('allowedUrls', []))
    network_urls = set(network_config.get('allowedUrls', []))
    
    missing_urls = golden_urls - network_urls
    extra_urls = network_urls - golden_urls
    
    if not differences and not missing_allowed and not extra_allowed and not missing_urls and not extra_urls:
        return None
    
    # Create recommendation
    recommendation = {
        'category': 'Security',
        'title': 'Malware Protection Settings',
        'overview': "Advanced Malware Protection (AMP) defends your network against malware, ransomware and other threats. Proper configuration is essential for security.",
        'actions': []
    }
    
    # Add action for mode differences
    if differences:
        action = {
            'action_type': 'Update AMP Mode',
            'description': "Update the Advanced Malware Protection mode to match golden configuration",
            'impact': 'Using a less protective mode may expose the network to malware threats',
            'severity': 'High',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Advanced Malware Protection in your Meraki dashboard',
                '2. Set the mode to match golden configuration:',
            ],
            'details': []
        }
        
        for diff in [d for d in differences if d['property'] == 'mode']:
            golden_mode = diff['golden_value']
            action['details'].append(f"Change mode from '{diff['network_value']}' to '{golden_mode}'")
            
            # Add explanation of the mode
            if golden_mode == 'enabled':
                action['details'].append("   - Enabled mode actively scans for and blocks malware")
            elif golden_mode == 'disabled':
                action['details'].append("   - Disabled mode turns off malware protection entirely")
                
        recommendation['actions'].append(action)
    
    # Add action for allowed files differences
    if missing_allowed or extra_allowed:
        action = {
            'action_type': 'Update Allowed Files',
            'description': "Update the allowed files list to match golden configuration",
            'impact': 'Different allowed files may create security inconsistencies across networks',
            'severity': 'Medium',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Advanced Malware Protection in your Meraki dashboard',
                '2. Under "Allowed files", make these changes:',
            ],
            'details': []
        }
        
        if missing_allowed:
            action['details'].append("Add the following file hashes to the allowed list:")
            for file_hash in missing_allowed:
                action['details'].append(f"   - {file_hash}")
        
        if extra_allowed:
            action['details'].append("Review and consider removing these extra file hashes that aren't in the golden image:")
            for file_hash in extra_allowed:
                action['details'].append(f"   - {file_hash}")
            
        recommendation['actions'].append(action)
    
    # Add action for allowed URLs differences
    if missing_urls or extra_urls:
        action = {
            'action_type': 'Update Allowed URLs',
            'description': "Update the allowed URLs list to match golden configuration",
            'impact': 'Different allowed URLs may create security inconsistencies across networks',
            'severity': 'Medium',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Advanced Malware Protection in your Meraki dashboard',
                '2. Under "Allowed URLs", make these changes:',
            ],
            'details': []
        }
        
        if missing_urls:
            action['details'].append("Add the following URLs to the allowed list:")
            for url in missing_urls:
                action['details'].append(f"   - {url}")
        
        if extra_urls:
            action['details'].append("Review and consider removing these extra URLs that aren't in the golden image:")
            for url in extra_urls:
                action['details'].append(f"   - {url}")
            
        recommendation['actions'].append(action)
    
    return recommendation

def recommend_static_routes_fixes(golden_config, network_config):
    """Generate detailed recommendations for static routes."""
    if not isinstance(golden_config, list) or not isinstance(network_config, list):
        return None
    
    # Helper function to identify a route uniquely
    def route_key(route):
        return f"{route.get('subnet', '')}-{route.get('name', '')}"
    
    # Create dictionaries of routes keyed by subnet+name for easy comparison
    golden_routes = {route_key(route): route for route in golden_config}
    network_routes = {route_key(route): route for route in network_config}
    
    # Find missing and extra routes
    missing_routes = [route for key, route in golden_routes.items() if key not in network_routes]
    extra_routes = [route for key, route in network_routes.items() if key not in golden_routes]
    
    # Find misconfigured routes
    misconfigured_routes = []
    for key, golden_route in golden_routes.items():
        if key in network_routes:
            network_route = network_routes[key]
            differences = []
            
            for prop in ['subnet', 'name', 'nextHop', 'enabled', 'fixedIpAssignment', 'advertiseToVpnPeers']:
                if golden_route.get(prop) != network_route.get(prop):
                    differences.append({
                        'property': prop,
                        'golden_value': golden_route.get(prop),
                        'network_value': network_route.get(prop)
                    })
            
            if differences:
                misconfigured_routes.append({
                    'route': golden_route,
                    'differences': differences
                })
    
    if not missing_routes and not extra_routes and not misconfigured_routes:
        return None
    
    # Create recommendation
    recommendation = {
        'category': 'Routing',
        'title': 'Static Routes Configuration',
        'overview': "Static routes determine how traffic is directed to specific subnets. Proper configuration is crucial for network connectivity between segments.",
        'actions': []
    }
    
    # Add action for missing routes
    if missing_routes:
        action = {
            'action_type': 'Add Missing Routes',
            'description': f"Add {len(missing_routes)} missing static routes to match golden configuration",
            'impact': 'Missing routes may prevent traffic from reaching certain network segments',
            'severity': 'High',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Static routes in your Meraki dashboard',
                '2. Click "Add a static route" for each missing route with these settings:',
            ],
            'details': []
        }
        
        for route in missing_routes:
            route_details = []
            route_details.append(f"Route to {route.get('subnet', 'unknown')} ({route.get('name', 'Unnamed')})")
            route_details.append(f"   - Next hop: {route.get('nextHop', 'Not specified')}")
            route_details.append(f"   - Enabled: {'Yes' if route.get('enabled', True) else 'No'}")
            
            if route.get('fixedIpAssignment'):
                route_details.append(f"   - Fixed IP Assignment: Yes")
                
            if route.get('advertiseToVpnPeers'):
                route_details.append(f"   - Advertise to VPN peers: Yes")
                
            action['details'].extend(route_details)
            
        recommendation['actions'].append(action)
    
    # Add action for misconfigured routes
    if misconfigured_routes:
        action = {
            'action_type': 'Fix Misconfigured Routes',
            'description': f"Update {len(misconfigured_routes)} existing routes to match golden configuration",
            'impact': 'Misconfigured routes may cause routing inconsistencies or connectivity issues',
            'severity': 'Medium',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Static routes in your Meraki dashboard',
                '2. Click on each route below and update with these changes:',
            ],
            'details': []
        }
        
        for item in misconfigured_routes:
            route = item['route']
            action['details'].append(f"Route to {route.get('subnet', 'unknown')} ({route.get('name', 'Unnamed')})")
            
            for diff in item['differences']:
                action['details'].append(f"   - Change {diff['property']} from '{diff['network_value']}' to '{diff['golden_value']}'")
                
        recommendation['actions'].append(action)
    
    # Add action for extra routes
    if extra_routes:
        action = {
            'action_type': 'Review Extra Routes',
            'description': f"Review {len(extra_routes)} routes that don't exist in the golden image",
            'impact': 'Extra routes may cause unexpected routing behavior',
            'severity': 'Low',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Static routes in your Meraki dashboard',
                '2. Review each route and determine if it should be kept:',
            ],
            'details': []
        }
        
        for route in extra_routes:
            action['details'].append(f"Route to {route.get('subnet', 'unknown')} ({route.get('name', 'Unnamed')}) with next hop {route.get('nextHop', 'unknown')}")
                
        recommendation['actions'].append(action)
    
    return recommendation

def recommend_traffic_shaping_fixes(golden_config, network_config):
    """Generate detailed recommendations for traffic shaping settings."""
    if not isinstance(golden_config, dict) or not isinstance(network_config, dict):
        return None
    
    differences = []
    
    # Compare basic settings
    for key in ['globalBandwidthLimits', 'defaultRulesEnabled']:
        if golden_config.get(key) != network_config.get(key):
            differences.append({
                'property': key,
                'golden_value': golden_config.get(key),
                'network_value': network_config.get(key),
                'impact': 'Affects how bandwidth is allocated across applications'
            })
    
    # Compare bandwidth limits if they exist
    if 'globalBandwidthLimits' in golden_config and 'globalBandwidthLimits' in network_config:
        golden_limits = golden_config['globalBandwidthLimits']
        network_limits = network_config['globalBandwidthLimits']
        
        for direction in ['limitUp', 'limitDown']:
            if golden_limits.get(direction) != network_limits.get(direction):
                differences.append({
                    'property': f'globalBandwidthLimits.{direction}',
                    'golden_value': golden_limits.get(direction),
                    'network_value': network_limits.get(direction),
                    'impact': f'Affects maximum {direction.replace("limit", "")} bandwidth'
                })
    
    # Compare rules if they exist
    golden_rules = golden_config.get('rules', [])
    network_rules = network_config.get('rules', [])
    
    # Helper function to identify a rule uniquely
    def rule_key(rule):
        return f"{rule.get('protocol', '')}-{rule.get('srcPort', '')}-{rule.get('dstPort', '')}"
    
    # Create dictionaries of rules for easy comparison
    golden_rules_dict = {rule_key(rule): rule for rule in golden_rules}
    network_rules_dict = {rule_key(rule): rule for rule in network_rules}
    
    # Find missing and extra rules
    missing_rules = [rule for key, rule in golden_rules_dict.items() if key not in network_rules_dict]
    extra_rules = [rule for key, rule in network_rules_dict.items() if key not in golden_rules_dict]
    
    if not differences and not missing_rules and not extra_rules:
        return None
    
    # Create recommendation
    recommendation = {
        'category': 'Traffic Management',
        'title': 'Traffic Shaping Configuration',
        'overview': "Traffic shaping rules prioritize and manage bandwidth for different applications. Proper configuration ensures critical applications get the resources they need.",
        'actions': []
    }
    
    # Add action for general settings
    if differences:
        action = {
            'action_type': 'Update Traffic Shaping Settings',
            'description': "Update general traffic shaping settings to match golden configuration",
            'impact': 'Inconsistent traffic shaping may affect application performance',
            'severity': 'Medium',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Traffic shaping in your Meraki dashboard',
                '2. Update the following settings:',
            ],
            'details': []
        }
        
        for diff in differences:
            action['details'].append(f"Change {diff['property']} from '{diff['network_value']}' to '{diff['golden_value']}'")
            if 'impact' in diff:
                action['details'].append(f"   - Impact: {diff['impact']}")
                
        recommendation['actions'].append(action)
    
    # Add action for missing rules
    if missing_rules:
        action = {
            'action_type': 'Add Missing Traffic Rules',
            'description': f"Add {len(missing_rules)} missing traffic shaping rules to match golden configuration",
            'impact': 'Missing rules may prevent proper prioritization of important applications',
            'severity': 'Medium',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Traffic shaping in your Meraki dashboard',
                '2. In the "Custom rules" section, add the following rules:',
            ],
            'details': []
        }
        
        for rule in missing_rules:
            rule_details = []
            src_port = rule.get('srcPort', 'Any')
            dst_port = rule.get('dstPort', 'Any')
            protocol = rule.get('protocol', 'Any')
            
            rule_details.append(f"Rule for {protocol} traffic: {src_port} → {dst_port}")
            
            if 'perClientBandwidthLimits' in rule:
                limits = rule['perClientBandwidthLimits']
                rule_details.append(f"   - Per-client limits: Up {limits.get('limitUp', 'unlimited')}, Down {limits.get('limitDown', 'unlimited')}")
                
            if 'priority' in rule:
                rule_details.append(f"   - Priority: {rule.get('priority', 'normal')}")
                
            action['details'].extend(rule_details)
            
        recommendation['actions'].append(action)
    
    # Add action for extra rules
    if extra_rules:
        action = {
            'action_type': 'Review Extra Traffic Rules',
            'description': f"Review {len(extra_rules)} traffic rules that don't exist in the golden image",
            'impact': 'Extra rules may cause unexpected traffic prioritization',
            'severity': 'Low',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Traffic shaping in your Meraki dashboard',
                '2. Review each rule and determine if it should be kept:',
            ],
            'details': []
        }
        
        for rule in extra_rules:
            src_port = rule.get('srcPort', 'Any')
            dst_port = rule.get('dstPort', 'Any')
            protocol = rule.get('protocol', 'Any')
            
            action['details'].append(f"Rule for {protocol} traffic: {src_port} → {dst_port}")
                
        recommendation['actions'].append(action)
    
    return recommendation

def recommend_vpn_fixes(golden_config, network_config):
    """Generate detailed recommendations for VPN configurations."""
    if not isinstance(golden_config, dict) or not isinstance(network_config, dict):
        return None
    
    differences = []
    
    # Compare mode
    if golden_config.get('mode') != network_config.get('mode'):
        differences.append({
            'property': 'mode',
            'golden_value': golden_config.get('mode'),
            'network_value': network_config.get('mode'),
            'impact': 'VPN operating mode affects entire VPN functionality',
            'severity': 'Critical'
        })
    
    # Compare hub configurations if they exist
    golden_hubs = golden_config.get('hubs', [])
    network_hubs = network_config.get('hubs', [])
    
    # Helper function to identify a hub uniquely
    def hub_key(hub):
        return hub.get('hubId', '')
    
    # Create dictionaries of hubs for easy comparison
    golden_hubs_dict = {hub_key(hub): hub for hub in golden_hubs}
    network_hubs_dict = {hub_key(hub): hub for hub in network_hubs}
    
    # Find missing and extra hubs
    missing_hubs = [hub for key, hub in golden_hubs_dict.items() if key not in network_hubs_dict]
    extra_hubs = [hub for key, hub in network_hubs_dict.items() if key not in golden_hubs_dict]
    
    # Compare subnets if they exist
    golden_subnets = golden_config.get('subnets', [])
    network_subnets = network_config.get('subnets', [])
    
    missing_subnets = [subnet for subnet in golden_subnets if subnet not in network_subnets]
    extra_subnets = [subnet for subnet in network_subnets if subnet not in golden_subnets]
    
    if not differences and not missing_hubs and not extra_hubs and not missing_subnets and not extra_subnets:
        return None
    
    # Create recommendation
    recommendation = {
        'category': 'VPN',
        'title': 'Site-to-Site VPN Configuration',
        'overview': "Site-to-Site VPN connects different network locations securely. Proper configuration ensures reliable and secure connectivity between sites.",
        'actions': []
    }
    
    # Add action for mode differences
    if any(d['property'] == 'mode' for d in differences):
        mode_diff = next(d for d in differences if d['property'] == 'mode')
        
        action = {
            'action_type': 'Update VPN Mode',
            'description': "Update the VPN mode to match golden configuration",
            'impact': 'VPN mode mismatch may cause connectivity failures with other sites',
            'severity': 'Critical',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Site-to-site VPN in your Meraki dashboard',
                '2. Select the correct VPN mode:',
            ],
            'details': []
        }
        
        golden_mode = mode_diff['golden_value']
        action['details'].append(f"Change mode from '{mode_diff['network_value']}' to '{golden_mode}'")
        
        # Add explanation of the mode
        if golden_mode == 'hub':
            action['details'].append("   - Hub mode: This network acts as a central hub for other spoke networks")
        elif golden_mode == 'spoke':
            action['details'].append("   - Spoke mode: This network connects to one or more hub networks")
        elif golden_mode == 'none':
            action['details'].append("   - None: VPN is disabled")
            
        recommendation['actions'].append(action)
    
    # Add action for missing hubs
    if missing_hubs:
        action = {
            'action_type': 'Add Missing VPN Hubs',
            'description': f"Add {len(missing_hubs)} missing VPN hub connections to match golden configuration",
            'impact': 'Missing hub connections may prevent this network from routing to other locations',
            'severity': 'High',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Site-to-site VPN in your Meraki dashboard',
                '2. In the "Hubs" section, add the following hub connections:',
            ],
            'details': []
        }
        
        for hub in missing_hubs:
            hub_details = []
            hub_details.append(f"Hub: {hub.get('hubId', 'unknown')} (Use weight: {hub.get('useDefaultRoute', False)})")
            
            action['details'].extend(hub_details)
            
        recommendation['actions'].append(action)
    
    # Add action for missing subnets
    if missing_subnets:
        action = {
            'action_type': 'Add Missing VPN Subnets',
            'description': f"Add {len(missing_subnets)} missing VPN subnets to match golden configuration",
            'impact': 'Missing subnets may prevent proper routing of traffic over the VPN',
            'severity': 'High',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Site-to-site VPN in your Meraki dashboard',
                '2. In the "Local networks" section, add the following subnets:',
            ],
            'details': []
        }
        
        for subnet in missing_subnets:
            action['details'].append(f"Subnet: {subnet.get('localSubnet', 'unknown')} (Use VPN: {subnet.get('useVpn', True)})")
            
        recommendation['actions'].append(action)
    
    # Add action for extra subnets
    if extra_subnets:
        action = {
            'action_type': 'Review Extra VPN Subnets',
            'description': f"Review {len(extra_subnets)} VPN subnets that don't exist in the golden image",
            'impact': 'Extra subnets may expose unintended resources over the VPN',
            'severity': 'Medium',
            'implementation_steps': [
                '1. Navigate to Security & SD-WAN > Configure > Site-to-site VPN in your Meraki dashboard',
                '2. Review the following subnets and determine if they should be removed:',
            ],
            'details': []
        }
        
        for subnet in extra_subnets:
            action['details'].append(f"Subnet: {subnet.get('localSubnet', 'unknown')} (Use VPN: {subnet.get('useVpn', True)})")
            
        recommendation['actions'].append(action)
    
    return recommendation

def generate_generic_recommendation(check_name, golden_config=None, network_config=None):
    """Generate enhanced generic recommendations for any configuration type, leveraging configuration type knowledge."""
    display_name = check_name.replace('getNetwork', '').replace('getOrganization', '').replace('Appliance', '').replace('Switch', '').lower()
    display_name = ' '.join(word.capitalize() for word in display_name.split())
    
    # Extract configuration type
    config_type = get_config_type(check_name)
    recommendation = {
        'category': config_type,
        'title': display_name,
        'overview': get_config_overview(check_name),
        'actions': [{
            'action_type': 'Review Configuration',
            'description': f"Review and update {display_name.lower()} settings to match golden image",
            'impact': get_config_impact(check_name),
            'severity': 'Medium',
            'implementation_steps': get_config_steps(check_name),
            'details': ["The current configuration doesn't match the golden image standard"]
        }]
    }
    
    # Add specific recommendations based on config type
    if golden_config and network_config:
        # Try to identify specific differences
        differences = identify_config_differences(check_name, golden_config, network_config)
        if differences:
            recommendation['actions'][0]['details'].extend(differences)
    
    return recommendation

#################################################################
#                      HELPER FUNCTIONS                         #
#################################################################

def are_rules_equivalent(rule1, rule2):
    """Check if two firewall rules are functionally equivalent."""
    # Key fields that determine rule equivalence
    key_fields = ['policy', 'protocol', 'srcCidr', 'destCidr', 'srcPort', 'destPort']
    
    for field in key_fields:
        if rule1.get(field) != rule2.get(field):
            return False
    
    return True

def format_rule_for_display(rule):
    """Format a firewall rule for human-readable display."""
    return (f"{rule.get('policy', 'unknown').upper()}: "
            f"{rule.get('srcCidr', 'Any')}:{rule.get('srcPort', 'Any')} → "
            f"{rule.get('destCidr', 'Any')}:{rule.get('destPort', 'Any')} "
            f"({rule.get('protocol', 'any')})")

def get_rule_impact(rule):
    """Determine the likely purpose and impact of a firewall rule."""
    policy = rule.get('policy', '').lower()
    protocol = rule.get('protocol', '').lower()
    dest_port = rule.get('destPort', '').lower()
    
    if policy == 'allow':
        if protocol == 'icmp':
            return "Allows ping/traceroute for network diagnostics"
        elif dest_port == '80' or dest_port == '443':
            return "Allows HTTP/HTTPS web traffic"
        elif dest_port == '53':
            return "Allows DNS resolution"
        elif dest_port == '25' or dest_port == '587' or dest_port == '465':
            return "Allows SMTP email traffic"
        elif dest_port == '22':
            return "Allows SSH administrative access"
        elif dest_port == '3389':
            return "Allows RDP remote desktop access"
    elif policy == 'deny':
        if rule.get('srcCidr') == 'Any' and rule.get('destCidr') == 'Any':
            return "Default deny rule (security best practice to block all traffic not explicitly allowed)"
    
    return None

def get_content_filtering_category_descriptions(categories):
    """Return descriptions for common content filtering categories."""
    descriptions = {
        "adult": "Adult/mature content including pornography",
        "gambling": "Sites related to gambling or betting",
        "weapons": "Sites about weapons, firearms, and explosives",
        "hacking": "Hacking, cracking and unauthorized system access sites",
        "drugs": "Illegal drugs and drug paraphernalia",
        "malware": "Sites hosting malware or virus distribution",
        "phishing": "Phishing and identity theft sites",
        "socialnetworking": "Social networking platforms",
        "blogging": "Personal blogs and journaling sites",
        "games": "Online gaming sites",
        "p2p": "Peer-to-peer file sharing sites",
        "proxy": "Proxy and anonymization services that bypass filtering",
        "streaming": "Video and audio streaming services",
        "advertising": "Web advertisement sites and ad networks",
        "unknown": "Uncategorized sites"
    }
    
    return {cat: descriptions.get(cat.lower(), "") for cat in categories}

def get_vlan_property_impact(property_name):
    """Return impact statements for VLAN property differences."""
    impacts = {
        "name": "Inconsistent naming may cause confusion in network management",
        "subnet": "Subnet mismatch may cause routing and connectivity issues",
        "applianceIp": "Appliance IP mismatch may cause gateway connectivity problems",
        "dhcpHandling": "DHCP configuration difference affects how clients receive IP addresses",
        "dhcpLeaseTime": "Affects how often clients need to renew their IP addresses",
        "dnsNameservers": "Different DNS servers may cause resolution inconsistencies"
    }
    
    return impacts.get(property_name, "Configuration inconsistency with golden image")

def get_ssid_property_impact(property_name):
    """Return impact statements for SSID property differences."""
    impacts = {
        "name": "Inconsistent SSID naming may cause user confusion",
        "visible": "Hidden SSIDs provide a minor security enhancement but may affect user experience",
        "authMode": "Authentication mode directly impacts wireless security posture",
        "encryptionMode": "Encryption mode is critical for wireless traffic security",
        "wpaEncryptionMode": "WPA mode affects wireless security strength",
        "ipAssignmentMode": "Affects how clients receive IP addresses",
        "minBitrate": "Minimum bitrate affects wireless performance and range",
        "bandSelection": "Band selection affects device compatibility and performance"
    }
    
    return impacts.get(property_name, "Configuration inconsistency with golden image")

def get_ssid_severity(property_name, golden_value, network_value):
    """Determine the severity of SSID property differences."""
    # Critical security issues
    if property_name == 'authMode':
        if network_value == 'open' and golden_value != 'open':
            return 'Critical'
        return 'High'
    
    if property_name == 'encryptionMode':
        if network_value == 'wep':
            return 'Critical'  # WEP is fundamentally insecure
        return 'High'
    
    if property_name == 'wpaEncryptionMode':
        if network_value == 'WPA1' and golden_value != 'WPA1':
            return 'High'  # WPA1 is less secure than WPA2/WPA3
        return 'Medium'
    
    # Medium impact issues
    if property_name in ['ipAssignmentMode', 'bandSelection']:
        return 'Medium'
    
    # Lower impact issues
    if property_name in ['name', 'visible', 'minBitrate']:
        return 'Low'
    
    return 'Medium'  # Default severity

def get_config_type(check_name):
    """Determine the configuration category from the check name."""
    check_name = check_name.lower()
    
    if 'firewall' in check_name:
        return 'Firewall'
    elif 'content' in check_name:
        return 'Content Filtering'
    elif 'vlan' in check_name:
        return 'VLANs'
    elif 'wireless' in check_name or 'ssid' in check_name:
        return 'Wireless'
    elif 'security' in check_name:
        return 'Security'
    elif 'vpn' in check_name:
        return 'VPN'
    elif 'traffic' in check_name:
        return 'Traffic Management'
    elif 'switch' in check_name:
        return 'Switch'
    elif 'route' in check_name:
        return 'Routing'
    else:
        return 'General'

def get_config_overview(check_name):
    """Provide context about the importance of this configuration type."""
    config_type = get_config_type(check_name)
    
    overviews = {
        'Firewall': "Firewall rules control traffic flow in your network and are critical for security. Different rules between networks may create security gaps.",
        'Content Filtering': "Content filtering protects your network by controlling access to websites. Inconsistent filtering may expose some networks to risks.",
        'VLANs': "VLANs segment your network and control traffic flow between different segments. Proper configuration is critical for security.",
        'Wireless': "Wireless configurations determine how users connect to your network. Security settings are particularly important to protect from unauthorized access.",
        'Security': "Security features protect your network from various threats. Inconsistent security settings may leave some networks vulnerable.",
        'VPN': "VPN connections securely link different parts of your network. Configuration differences may cause connection issues or security gaps.",
        'Traffic Management': "Traffic management settings prioritize important network traffic. Inconsistencies may affect application performance.",
        'Switch': "Switch configurations control how your wired network devices communicate. Differences may affect performance and security.",
        'Routing': "Routing configurations determine how traffic moves between different network segments. Inconsistencies may cause connectivity issues."
    }
    
    return overviews.get(config_type, f"This configuration affects how your Meraki network operates. Differences from the golden image may cause functionality or security issues.")

def get_config_impact(check_name):
    """Provide impact statement for this configuration type."""
    config_type = get_config_type(check_name)
    
    impacts = {
        'Firewall': "Inconsistent firewall rules may create security vulnerabilities or block legitimate traffic",
        'Content Filtering': "Inconsistent content filtering may allow access to prohibited content in some networks",
        'VLANs': "VLAN misconfiguration may cause network segmentation issues or IP addressing conflicts",
        'Wireless': "Wireless configuration differences may affect security posture and user connectivity experience",
        'Security': "Security feature differences may leave some networks more vulnerable to threats",
        'VPN': "VPN configuration differences may cause connection failures or security weaknesses",
        'Traffic Management': "Traffic management inconsistencies may result in poor application performance",
        'Switch': "Switch configuration differences may affect network performance and security",
        'Routing': "Routing inconsistencies may cause traffic flow issues or unexpected network behavior"
    }
    
    return impacts.get(config_type, "Configuration inconsistencies may cause operational or security issues")

def get_config_steps(check_name):
    """Provide implementation steps based on configuration type."""
    check_lower = check_name.lower()
    
    # Determine the navigation path based on check name
    if 'firewalll3' in check_lower:
        return [
            '1. Navigate to Security & SD-WAN > Configure > Firewall in your Meraki dashboard',
            '2. Review the L3 Firewall Rules section'
        ]
    elif 'firewallport' in check_lower:
        return [
            '1. Navigate to Security & SD-WAN > Configure > Firewall in your Meraki dashboard',
            '2. Select the Port Forwarding tab'
        ]
    elif 'content' in check_lower:
        return [
            '1. Navigate to Security & SD-WAN > Configure > Content filtering in your Meraki dashboard'
        ]
    elif 'vlan' in check_lower:
        return [
            '1. Navigate to Security & SD-WAN > Configure > Addressing & VLANs in your Meraki dashboard'
        ]
    elif 'ssid' in check_lower:
        return [
            '1. Navigate to Wireless > Configure > SSIDs in your Meraki dashboard'
        ]
    elif 'wireless' in check_lower and 'rf' in check_lower:
        return [
            '1. Navigate to Wireless > Configure > RF profiles in your Meraki dashboard'
        ]
    elif 'wireless' in check_lower:
        return [
            '1. Navigate to Wireless > Configure in your Meraki dashboard'
        ]
    elif 'intrusion' in check_lower:
        return [
            '1. Navigate to Security & SD-WAN > Configure > Threat protection in your Meraki dashboard'
        ]
    elif 'malware' in check_lower:
        return [
            '1. Navigate to Security & SD-WAN > Configure > Advanced Malware Protection in your Meraki dashboard'
        ]
    elif 'traffic' in check_lower:
        return [
            '1. Navigate to Security & SD-WAN > Configure > Traffic shaping in your Meraki dashboard'
        ]
    elif 'vpn' in check_lower:
        return [
            '1. Navigate to Security & SD-WAN > Configure > Site-to-site VPN in your Meraki dashboard'
        ]
    elif 'switch' in check_lower:
        return [
            '1. Navigate to Switch > Configure in your Meraki dashboard'
        ]
    elif 'staticroute' in check_lower:
        return [
            '1. Navigate to Security & SD-WAN > Configure > Static routes in your Meraki dashboard'
        ]
    
    # Generic steps if no specific match
    return [
        '1. Navigate to the appropriate configuration section in your Meraki dashboard',
        '2. Compare current settings with golden image and update accordingly'
        ]
def identify_config_differences(check_name, golden_config, network_config):
    """Attempt to identify specific differences between configurations."""
    # Try to extract main keys
    differences = []
    check_key = check_name.replace('getNetwork', '').replace('getOrganization', '').replace('Appliance', '').replace('Switch', '').lower()
    
    # Handle different data formats
    if isinstance(golden_config, dict) and check_key in golden_config:
        golden_data = golden_config[check_key]
    else:
        golden_data = golden_config
    
    if isinstance(network_config, dict) and check_key in network_config:
        network_data = network_config[check_key]
    else:
        network_data = network_config
    
    # Simple comparison for scalar values
    if not isinstance(golden_data, (dict, list)) and not isinstance(network_data, (dict, list)):
        if golden_data != network_data:
            differences.append(f"Change value from '{network_data}' to '{golden_data}'")
        return differences
    
    # For dictionaries, compare key by key
    if isinstance(golden_data, dict) and isinstance(network_data, dict):
        for key, value in golden_data.items():
            if key not in network_data:
                differences.append(f"Add missing setting: {key} = {value}")
            elif network_data[key] != value:
                differences.append(f"Update {key} from '{network_data[key]}' to '{value}'")
        
        # Look for extra keys in network config
        for key in network_data:
            if key not in golden_data:
                differences.append(f"Review extra setting in network: {key} = {network_data[key]}")
    
    # For lists, find items in golden that aren't in network
    elif isinstance(golden_data, list) and isinstance(network_data, list):
        # This is simplified and might not work for all list types
        for item in golden_data:
            if item not in network_data:
                differences.append(f"Add missing item: {item}")
        
        for item in network_data:
            if item not in golden_data:
                differences.append(f"Review extra item in network: {item}")
    
    return differences

#################################################################
#                     MAIN ANALYSIS FUNCTION                    #
#################################################################

def analyze_compliance_data(non_compliant_results=None, directory='./'):
    """
    Main function to run all AI analysis on compliance data.
    
    Args:
        non_compliant_results: Results from compliance check (optional)
        directory: Base directory where configs are stored
        
    Returns:
        Dictionary with analysis results
    """
    # Load configurations
    golden_configs, network_configs, org_network_mapping = load_network_configs(directory)
    
    if not golden_configs or not network_configs:
        logging.error("No configuration data found")
        return {
            "error": "No configuration data found"
        }
    
    # Load non-compliant results if not provided
    if non_compliant_results is None:
        try:
            # Parse the non-compliant networks from the table file
            non_compliant_results = parse_non_compliant_table('non_compliant_networks_table.txt')
            logging.debug(f"Loaded non-compliant data: {len(non_compliant_results)} networks")
        except Exception as e:
            logging.error(f"Error parsing non-compliant data: {e}")
            non_compliant_results = {}
    
    # Run analyses
    anomalies = detect_meraki_anomalies(network_configs)
    recommendations = generate_compliance_recommendations(golden_configs, network_configs, non_compliant_results)
    
    return {
        "anomalies": anomalies,
        "recommendations": recommendations
    }

def load_network_configs(directory='./'):
    """
    Load network configurations from the standard directory structure.
    
    Returns:
        tuple: (golden_configs, network_configs, org_network_mapping)
    """
    import os
    
    golden_configs = {}
    network_configs = {}
    org_network_mapping = defaultdict(list)
    
    # Scan for organization directories
    for item in os.listdir(directory):
        if item.startswith('Org_') and os.path.isdir(os.path.join(directory, item)):
            org_dir = os.path.join(directory, item)
            org_name = item.replace('Org_', '')
            
            # Look for golden image data
            for subitem in os.listdir(org_dir):
                # Golden image directory
                if 'GoldenImage' in subitem and os.path.isdir(os.path.join(org_dir, subitem)):
                    golden_dir = os.path.join(org_dir, subitem)
                    try:
                        with open(os.path.join(golden_dir, 'golden_image_data.json'), 'r') as f:
                            golden_data = json.load(f)
                            golden_configs[org_name] = golden_data
                    except (FileNotFoundError, json.JSONDecodeError) as e:
                        logging.error(f"Error loading golden data for {org_name}: {e}")
                
                # Network directory
                elif 'ComplianceCheck' in subitem and os.path.isdir(os.path.join(org_dir, subitem)):
                    network_dir = os.path.join(org_dir, subitem)
                    network_name = subitem.replace('_ComplianceCheck', '')
                    
                    try:
                        with open(os.path.join(network_dir, 'network_data.json'), 'r') as f:
                            network_data = json.load(f)
                            network_configs[network_name] = network_data
                            org_network_mapping[org_name].append(network_name)
                    except (FileNotFoundError, json.JSONDecodeError) as e:
                        logging.error(f"Error loading network data for {network_name}: {e}")
    
    return golden_configs, network_configs, org_network_mapping

def parse_non_compliant_table(table_file):
    """Parse non-compliant networks from the table file format."""
    result = {}
    
    try:
        with open(table_file, 'r') as f:
            lines = f.readlines()
        
        # Skip header lines (first few lines of the table)
        data_lines = [line.strip() for line in lines if line.strip() and '|' in line][2:]
        
        # Process each line
        for line in data_lines:
            # Split by | and remove whitespace
            parts = [part.strip() for part in line.split('|') if part.strip()]
            if len(parts) >= 4:
                org_name = parts[0]
                network_name = parts[1]
                network_id = None
                
                # Find network ID from name - we need to look this up
                # For now, create a temporary placeholder structure
                if network_name not in result:
                    result[network_name] = {
                        'network_info': {},
                        'non_compliant_checks': []
                    }
                
                # Extract specific check that failed
                if len(parts) > 2:
                    check_name = parts[2]
                    # Convert display name to API check name (approximate mapping)
                    api_check = convert_display_to_api_check(check_name)
                    if api_check and api_check not in result[network_name]['non_compliant_checks']:
                        result[network_name]['non_compliant_checks'].append(api_check)
        
        logging.info(f"Parsed {len(result)} non-compliant networks from table")
        return result
    
    except Exception as e:
        logging.error(f"Error parsing non-compliant table: {e}")
        return {}

def convert_display_to_api_check(display_name):
    """Convert a display name to API check name."""
    # This is a simplified version - you'll need to expand this mapping
    mappings = {
        'Connectivity Monitoring': 'getNetworkApplianceConnectivityMonitoringDestinations',
        'Content Filtering': 'getNetworkApplianceContentFiltering',
        'L3 Firewall Rules': 'getNetworkApplianceFirewallL3FirewallRules',
        'Inbound Firewall Rules': 'getNetworkApplianceFirewallInboundFirewallRules',
        'VLANs': 'getNetworkApplianceVlans',
        'Warm Spare': 'getNetworkApplianceWarmSpare',
        'Storm Control': 'getNetworkSwitchStormControl',
        'STP': 'getNetworkSwitchStp',
        'Wireless SSIDs': 'getNetworkWirelessSsids'
    }
    
    # Try direct mapping first
    if display_name in mappings:
        return mappings[display_name]
    
    # Try partial matching
    for display, api in mappings.items():
        if display in display_name or display_name in display:
            return api
    
    # No match found
    logging.warning(f"Could not map display name '{display_name}' to API check name")
    return None

if __name__ == "__main__":
    results = analyze_compliance_data()
    print(json.dumps(results, indent=2))