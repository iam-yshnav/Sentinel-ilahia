
from app import db
from app.models import Asset, ThreatIntelligence

def version_to_tuple(version_str):
    """
    Convert a version string like '3.2.1' or '2.2' into a tuple of integers (3, 2, 1) or (2, 2)
    for easy comparison.
    """
    try:
        return tuple(int(part) for part in version_str.split('.'))
    except Exception:
        return None

def compare_versions(v1, v2):
    """
    Compare two version tuples.
    
    Returns:
        -1 if v1 < v2,
         1 if v1 > v2,
         0 if equal.
    
    This function pads the shorter tuple with zeros so that versions like "2.2"
    become comparable with "2.2.1" (treated as "2.2.0").
    """
    len1, len2 = len(v1), len(v2)
    max_len = max(len1, len2)
    padded_v1 = v1 + (0,) * (max_len - len1)
    padded_v2 = v2 + (0,) * (max_len - len2)
    
    if padded_v1 < padded_v2:
        return -1
    elif padded_v1 > padded_v2:
        return 1
    else:
        return 0

def is_vulnerable_version(asset_version, condition):
    """
    Determines whether an asset's version satisfies the given condition.
    
    Parameters:
        asset_version (str): The version from the asset (e.g., "3.2.1")
        condition (str): The vulnerability condition. This could be:
                         - "<3.5" : asset version should be less than 3.5
                         - ">4.0" : asset version should be greater than 4.0
                         - "3.0-3.5" : asset version should be between 3.0 and 3.5 (inclusive)
                         - "3.2.1" : asset version must match exactly
        
    Returns:
        bool: True if the asset_version meets the condition, False otherwise.
    """
    asset_tuple = version_to_tuple(asset_version)
    if not asset_tuple:
        return False

    condition = condition.strip()
    
    # Check for less-than condition
    if condition.startswith('<'):
        cond_version = condition[1:].strip()
        cond_tuple = version_to_tuple(cond_version)
        if not cond_tuple:
            return False
        return compare_versions(asset_tuple, cond_tuple) < 0
    
    # Check for greater-than condition
    elif condition.startswith('>'):
        cond_version = condition[1:].strip()
        cond_tuple = version_to_tuple(cond_version)
        if not cond_tuple:
            return False
        return compare_versions(asset_tuple, cond_tuple) > 0
    
    # Check for a range (e.g., "3.0-3.5")
    elif '-' in condition:
        try:
            min_version, max_version = [part.strip() for part in condition.split('-')]
            min_tuple = version_to_tuple(min_version)
            max_tuple = version_to_tuple(max_version)
            if not min_tuple or not max_tuple:
                return False
        except Exception:
            return False
        return compare_versions(asset_tuple, min_tuple) >= 0 and compare_versions(asset_tuple, max_tuple) <= 0
    
    # Otherwise, expect an exact version match
    else:
        cond_tuple = version_to_tuple(condition)
        if not cond_tuple:
            return False
        return compare_versions(asset_tuple, cond_tuple) == 0

def search_vulnerable_assets(threat_report):
    """
    Searches for assets that match the vulnerability criteria specified in a threat report.
    
    Parameters:
        threat_report: An instance of ThreatReport which contains:
            - affected_platforms (OS name)
            - affected_platform_ver (OS version condition)
            - affected_service (Service name)
            - affected_service_ver (Service version condition)
    
    Returns:
        List of Asset instances that are considered vulnerable.
    """
    # Initial query: Filter assets by matching OS and service names
    assets = Asset.query.filter(
        Asset.os_name == threat_report.affected_platforms,
        Asset.service_name == threat_report.affected_service
    ).all() # This fetches most of them, but we need to further filter by version
    print(f"Found {len(assets)} assets with matching OS and service names.")
    vulnerable_assets = []  
    for asset in assets:
        # Check if both OS version and service version meet the vulnerability criteria
        os_vulnerable = is_vulnerable_version(asset.os_version, threat_report.affected_platform_ver)
        service_vulnerable = is_vulnerable_version(asset.service_version, threat_report.affected_service_ver)
        
        if os_vulnerable and service_vulnerable:
            vulnerable_assets.append(asset)

    print(f"Found {len(vulnerable_assets)} vulnerable assets.")
    return vulnerable_assets

def add_vulnerable_assets_to_threat_intel(threat_report):
    """
    For each vulnerable asset found based on the threat report criteria,
    add an entry into the ThreatIntelligence table.
    
    The new record will include the organization id, asset id, server name,
    threat id, and an initial state (e.g., 'triaged').
    """
    print(f"Searching for vulnerable assets based on threat report: {threat_report.threat_title}")
    vulnerable_assets = search_vulnerable_assets(threat_report)
    
    for asset in vulnerable_assets:
        threat_intel = ThreatIntelligence(
            organization_id=asset.organization_id,
            asset_id=asset.id,
            server_name=asset.server_name,
            threat_id=threat_report.id,
            state='triaged'  # You can change the initial state as needed
        )
        db.session.add(threat_intel)
    db.session.commit()
    return vulnerable_assets

# Example usage:
# Assume threat_report is an instance of ThreatReport that has just been added.
# vulnerable = add_vulnerable_assets_to_threat_intel(threat_report)
# print(f"Found {len(vulnerable)} vulnerable assets.")
