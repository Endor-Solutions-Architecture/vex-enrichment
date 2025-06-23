import os
import sys
import requests
import json
from datetime import datetime
from dotenv import load_dotenv
import urllib.parse
import argparse

# Load the environment variables from the .env file
load_dotenv()

# API Configuration
API_URL = 'https://api.endorlabs.com/v1'

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Enrich VEX documents from Endor Labs with exception policy information.'
    )
    parser.add_argument(
        '--namespace',
        help='The Endor Labs namespace to use. If not provided, will fall back to ENDOR_NAMESPACE environment variable.',
        default=os.getenv("ENDOR_NAMESPACE")
    )
    parser.add_argument(
        '--package-uuids',
        help='Comma-separated list of package UUIDs to process. If not provided, UUIDs will be fetched from the namespace.',
        type=str
    )
    parser.add_argument(
        '--export-sbom',
        help='Also export an SBOM for the packages.',
        action='store_true'
    )
    return parser.parse_args()

def check_env_vars(namespace):
    """Check if all required environment variables and arguments are set."""
    required_vars = {
        "API_KEY": os.getenv("API_KEY"),
        "API_SECRET": os.getenv("API_SECRET")
    }
    
    # Only check for namespace if package UUIDs weren't provided
    if not hasattr(parse_args(), 'package_uuids') or not parse_args().package_uuids:
        required_vars["Namespace"] = namespace
    
    missing_vars = [var for var, value in required_vars.items() if not value]
    
    if missing_vars:
        print("Error: The following required values are not set:")
        for var in missing_vars:
            if var == "Namespace":
                print("- Namespace (provide via --namespace argument or ENDOR_NAMESPACE environment variable)")
            else:
                print(f"- {var} (environment variable)")
        sys.exit(1)

def get_token():
    """Get authentication token from Endor Labs API."""
    api_key = os.getenv("API_KEY")
    api_secret = os.getenv("API_SECRET")
    url = f"{API_URL}/auth/api-key"
    payload = {
        "key": api_key,
        "secret": api_secret
    }
    headers = {
        "Content-Type": "application/json",
        "Request-Timeout": "60"
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=60)
        response.raise_for_status()
        token = response.json().get('token')
        return token
    except requests.exceptions.RequestException as e:
        print(f"Error getting authentication token: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response status code: {e.response.status_code}")
            print(f"Response text: {e.response.text}")
        sys.exit(1)

def get_package_uuids(token, namespace):
    """Fetch package UUIDs from the namespace."""
    filter_param = "context.type==CONTEXT_TYPE_MAIN and spec.ecosystem != ECOSYSTEM_GITHUB_ACTION"
    encoded_filter = urllib.parse.quote(filter_param)
    
    url = f"{API_URL}/namespaces/{namespace}/package-versions"
    params = {
        "list_parameters.filter": filter_param,
        "list_parameters.mask": "uuid"
    }
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}"
    }

    try:
        response = requests.get(url, params=params, headers=headers, timeout=60)
        response.raise_for_status()
        data = response.json()
        
        package_uuids = []
        if 'list' in data and 'objects' in data['list']:
            package_uuids = [obj.get('uuid') for obj in data['list']['objects'] if obj.get('uuid')]
            print(f"Found {len(package_uuids)} packages")
        return package_uuids
    except requests.exceptions.RequestException as e:
        print(f"Error fetching package UUIDs: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response text: {e.response.text}")
        sys.exit(1)

def get_policy_details(token, policy_uuid, namespace):
    """Fetch details for a specific policy UUID by walking up the namespace tree."""
    # Split namespace into parts and try each level
    namespace_parts = namespace.split('.')
    
    # Try each namespace level, starting from the most specific
    while namespace_parts:
        current_namespace = '.'.join(namespace_parts)
        url = f"{API_URL}/namespaces/{current_namespace}/policies/{policy_uuid}"
        
        params = {
            "get_parameters.mask": "spec.exception,meta.description,meta.tags,meta.create_time,meta.update_time"
        }
        
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}"
        }

        try:
            response = requests.get(url, params=params, headers=headers, timeout=60)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None and e.response.status_code == 404:
                # Try the parent namespace
                namespace_parts.pop()
                continue
            else:
                print(f"Error fetching policy {policy_uuid}: {str(e)}")
                if hasattr(e, 'response') and e.response is not None:
                    print(f"Response text: {e.response.text}")
                return None
    
    # If we've tried all namespace levels and still haven't found it
    return None

def get_findings_with_exceptions(token, package_uuids, namespace):
    """Get findings that have exceptions applied to them for the given package UUIDs."""
    url = f"{API_URL}/namespaces/{namespace}/optimized-queries"
    
    # Create filter condition for all package UUIDs
    uuid_conditions = [f'meta.parent_uuid=="{uuid}"' for uuid in package_uuids]
    uuid_filter = "(" + " or ".join(uuid_conditions) + ")"
    
    # Combine with the rest of the filter conditions
    filter_condition = f"{uuid_filter} and context.type == \"CONTEXT_TYPE_MAIN\" and ((spec.finding_categories contains [\"FINDING_CATEGORY_VULNERABILITY\"] and spec.exceptions.policy_uuids exists))"
    
    payload = {
        "meta": {
            "name": f"QueryFindings(namespace={namespace})"
        },
        "spec": {
            "query": {
                "kind": "Finding",
                "list_parameters": {
                    "filter": filter_condition,
                    "mask": "uuid,spec.exceptions",
                    "page_size": 500,
                    "sort": {
                        "path": "spec.level",
                        "order": "SORT_ENTRY_ORDER_ASC"
                    },
                    "traverse": True
                }
            }
        }
    }
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=60)
        response.raise_for_status()
        data = response.json()
        
        findings = []
        policy_uuids_set = set()
        if ('spec' in data and 'query_response' in data['spec'] and 
            'list' in data['spec']['query_response'] and 
            'objects' in data['spec']['query_response']['list']):
            
            findings = data['spec']['query_response']['list']['objects']
            for finding in findings:
                if 'spec' in finding and 'exceptions' in finding['spec'] and 'policy_uuids' in finding['spec']['exceptions']:
                    policy_uuids = finding['spec']['exceptions']['policy_uuids']
                    policy_uuids_set.update(policy_uuids)
        
        print(f"Found {len(findings)} findings with exceptions across {len(policy_uuids_set)} unique policies")
        
        # Fetch policy details for each unique policy UUID
        policies = {}
        missing_policies = set()
        for policy_uuid in policy_uuids_set:
            policy_data = get_policy_details(token, policy_uuid, namespace)
            if policy_data:
                policies[policy_uuid] = policy_data
            else:
                missing_policies.add(policy_uuid)
        
        # Print warnings for findings with missing policies
        if missing_policies:
            print("\nWarning: The following findings reference non-existent policies:")
            for finding in findings:
                if ('spec' in finding and 'exceptions' in finding['spec'] and 
                    'policy_uuids' in finding['spec']['exceptions']):
                    referenced_missing = set(finding['spec']['exceptions']['policy_uuids']) & missing_policies
                    if referenced_missing:
                        finding_id = finding.get('uuid', 'unknown')
                        policies_str = ', '.join(referenced_missing)
                        print(f"  - Finding {finding_id} references missing policies: {policies_str}. Please re-scan the packages.")
        
        return findings, policies
    except requests.exceptions.RequestException as e:
        print(f"Error fetching findings with exceptions: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response text: {e.response.text}")
        sys.exit(1)

def export_vex(token, package_uuids, namespace, export_name=None):
    """Export VEX document for the specified package UUIDs."""
    url = f"{API_URL}/namespaces/{namespace}/vex-export"
    
    if not export_name:
        export_name = f"VEX Export: {namespace}"
    
    payload = {
        "tenant_meta": {
            "namespace": namespace
        },
        "meta": {
            "name": export_name
        },
        "spec": {
            "kind": "SBOM_KIND_CYCLONEDX",
            "component_type": "COMPONENT_TYPE_APPLICATION",
            "format": "FORMAT_JSON",
            "export_parameters": {
                "package_version_uuids": package_uuids
            }
        }
    }
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}"
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=60)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error exporting VEX document: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response text: {e.response.text}")
        sys.exit(1)

def update_vex_with_exceptions(vex_data, findings, policies):
    """Update VEX document with analysis sections based on exception policies."""
    if not isinstance(vex_data, dict):
        vex_content = json.loads(vex_data)
    else:
        vex_content = vex_data
        
    # Define valid tags
    justification_tags = {
        'code_not_present', 'code_not_reachable', 'requires_configuration',
        'requires_dependency', 'requires_environment', 'protected_by_compiler',
        'protected_at_runtime', 'protected_at_perimeter', 'protected_by_mitigating_control'
    }
    
    response_tags = {
        'can_not_fix', 'will_not_fix', 'update', 'rollback', 'workaround_available'
    }
    
    # Map Endor exception reasons to ECMA-compliant VEX states
    reason_to_state = {
        "EXCEPTION_REASON_UNSPECIFIED": "in_triage",  # Default to in_triage when unspecified
        "EXCEPTION_REASON_FALSE_POSITIVE": "false_positive",  # Direct mapping
        "EXCEPTION_REASON_RISK_ACCEPTED": "exploitable",  # If risk is accepted, it means it's exploitable
        "EXCEPTION_REASON_IN_TRIAGE": "in_triage",  # Direct mapping
        "EXCEPTION_REASON_OTHER": "in_triage",  # Default to in_triage for other reasons
        "EXCEPTION_REASON_RESOLVED": "resolved"  # Direct mapping
    }
    
    # Ensure vulnerabilities list exists
    if 'vulnerabilities' not in vex_content:
        vex_content['vulnerabilities'] = []
    
    # Update each finding with its exception data
    for finding in findings:
        if ('spec' in finding and 'exceptions' in finding['spec'] and 
            'policy_uuids' in finding['spec']['exceptions']):
            for policy_uuid in finding['spec']['exceptions']['policy_uuids']:
                if policy_uuid in policies:
                    policy = policies[policy_uuid]
                    
                    # Extract policy data
                    exception_spec = policy.get('spec', {}).get('exception', {})
                    policy_meta = policy.get('meta', {})
                    policy_tags = policy_meta.get('tags', [])
                    
                    # Create analysis section
                    analysis = {
                        "state": reason_to_state.get(exception_spec.get('reason', ''), "in_triage"),
                        "firstIssued": policy_meta.get('create_time'),
                        "lastUpdated": policy_meta.get('update_time')
                    }
                    
                    # Add justification if matching tag exists
                    for tag in policy_tags:
                        if tag in justification_tags:
                            analysis["justification"] = tag
                            break
                    
                    # Add response if matching tags exist
                    response_matches = [tag for tag in policy_tags if tag in response_tags]
                    if response_matches:
                        analysis["response"] = response_matches
                    
                    # Add description if available
                    if 'description' in policy_meta:
                        analysis["detail"] = policy_meta['description']
                    
                    # Find matching vulnerability in VEX document
                    found = False
                    for vuln in vex_content['vulnerabilities']:
                        if 'affects' in vuln:
                            for affect in vuln['affects']:
                                if affect.get('ref') == finding.get('uuid'):
                                    vuln['analysis'] = analysis
                                    found = True
                                    break
                        if found:
                            break
                    
                    # If no matching vulnerability found, create a new one
                    if not found:
                        new_vuln = {
                            "affects": [{"ref": finding.get('uuid')}],
                            "analysis": analysis
                        }
                        vex_content['vulnerabilities'].append(new_vuln)
    
    return vex_content

def save_vex_document(vex_data, findings, policies, output_dir="vex_exports"):
    """Save VEX document to a file."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    if not isinstance(vex_data, dict) or 'spec' not in vex_data or 'data' not in vex_data['spec']:
        raise ValueError("Invalid VEX response format: missing spec.data")
    
    vex_content = vex_data['spec']['data']
    vex_content = update_vex_with_exceptions(vex_content, findings, policies)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"vex_export_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w') as f:
        json.dump(vex_content, f, indent=2)
    
    return filepath

def export_sbom(token, package_uuids, namespace, export_name=None):
    """Export SBOM document for the specified package UUIDs."""
    url = f"{API_URL}/namespaces/{namespace}/sbom-export"
    
    if not export_name:
        export_name = f"SBOM Export: {namespace}"
    
    payload = {
        "tenant_meta": {
            "namespace": namespace
        },
        "meta": {
            "name": export_name
        },
        "spec": {
            "kind": "SBOM_KIND_CYCLONEDX",
            "component_type": "COMPONENT_TYPE_APPLICATION",
            "format": "FORMAT_JSON",
            "export_parameters": {
                "package_version_uuids": package_uuids
            }
        }
    }
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}"
    }

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=60)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error exporting SBOM document: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Response text: {e.response.text}")
        sys.exit(1)

def save_sbom_document(sbom_data, output_dir="sbom_exports"):
    """Save SBOM document to a file."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    if not isinstance(sbom_data, dict) or 'spec' not in sbom_data or 'data' not in sbom_data['spec']:
        raise ValueError("Invalid SBOM response format: missing spec.data")
    
    sbom_content = sbom_data['spec']['data']
    if not isinstance(sbom_content, dict):
        sbom_content = json.loads(sbom_content)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"sbom_export_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w') as f:
        json.dump(sbom_content, f, indent=2)
    
    return filepath

def main():
    args = parse_args()
    check_env_vars(args.namespace)
    
    try:
        token = get_token()
        print("Successfully authenticated with Endor Labs API")
        
        # Get package UUIDs either from command line or by fetching them
        if args.package_uuids:
            package_uuids = [uuid.strip() for uuid in args.package_uuids.split(',')]
            print(f"Using {len(package_uuids)} provided package UUIDs")
        else:
            print("Fetching package UUIDs from namespace...")
            package_uuids = get_package_uuids(token, args.namespace)
        
        if not package_uuids:
            print("No package UUIDs available. Cannot proceed with export.")
            sys.exit(1)
        
        print("Fetching findings with exceptions...")
        findings, policies = get_findings_with_exceptions(token, package_uuids, args.namespace)
        
        print("Exporting VEX document...")
        vex_response = export_vex(token, package_uuids, args.namespace)
        output_file = save_vex_document(vex_response, findings, policies)
        print(f"VEX export completed successfully and saved to: {output_file}")
        
        if args.export_sbom:
            print("\nExporting SBOM document...")
            sbom_response = export_sbom(token, package_uuids, args.namespace)
            sbom_file = save_sbom_document(sbom_response)
            print(f"SBOM export completed successfully and saved to: {sbom_file}")
        
        return vex_response
    except Exception as e:
        print(f"Operation failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 