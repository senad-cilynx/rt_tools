#!/usr/bin/env python3
"""
BloodHound ZIP Analyzer - Attack Path Identification
Parses msldap BloodHound output to find:
- Domain Admin paths
- High-value targets with dangerous ACEs
- Kerberoastable admin accounts
- Accounts with DCSync rights
- Interesting group memberships
"""
import zipfile, json, sys, os
from collections import defaultdict

def load_json_from_zip(zf, filename):
    try:
        with zf.open(filename) as f:
            return json.loads(f.read())
    except:
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: bh_analyze.py <bloodhound.zip>")
        sys.exit(1)
    
    zippath = sys.argv[1]
    print(f"[*] Loading {zippath}...")
    zf = zipfile.ZipFile(zippath)
    files = zf.namelist()
    print(f"[*] Files: {len(files)}")

    # Load domains
    print("\n" + "="*60)
    print("DOMAIN INFO")
    print("="*60)
    for f in files:
        if 'domains' in f:
            data = load_json_from_zip(zf, f)
            if data and 'data' in data:
                for d in data['data']:
                    props = d.get('Properties', {})
                    print(f"  Domain: {props.get('name', 'N/A')}")
                    print(f"  Functional Level: {props.get('functionallevel', 'N/A')}")
                    print(f"  DC Count: {props.get('dccount', 'N/A')}")
                    if 'Trusts' in d:
                        print(f"  Trusts: {len(d['Trusts'])}")
                        for t in d['Trusts']:
                            print(f"    {t.get('TargetDomainName','N/A')} | Direction: {t.get('TrustDirection','N/A')} | Type: {t.get('TrustType','N/A')} | Transitive: {t.get('IsTransitive','N/A')}")

    # Analyze users - find high value targets
    print("\n" + "="*60)
    print("HIGH-VALUE USER ANALYSIS")
    print("="*60)
    
    da_members = []
    admin_users = []
    kerberoastable = []
    dcsync_users = []
    has_spn = []
    dont_preauth = []
    owned_accounts = []
    unconstraineddelegation = []
    all_aces = defaultdict(list)

    for f in files:
        if 'users' not in f:
            continue
        print(f"  [*] Processing {f}...")
        data = load_json_from_zip(zf, f)
        if not data or 'data' not in data:
            continue
        
        for user in data['data']:
            props = user.get('Properties', {})
            aces = user.get('Aces', [])
            name = props.get('name', 'UNKNOWN')
            sid = user.get('ObjectIdentifier', '')
            
            # Admin accounts
            if props.get('admincount', False):
                admin_users.append({
                    'name': name,
                    'enabled': props.get('enabled', False),
                    'hasspn': props.get('hasspn', False),
                    'description': props.get('description', ''),
                    'pwdlastset': props.get('pwdlastset', 0),
                    'lastlogon': props.get('lastlogon', 0),
                    'sensitive': props.get('sensitive', False),
                    'dontreqpreauth': props.get('dontreqpreauth', False),
                    'unconstraineddelegation': props.get('unconstraineddelegation', False),
                    'sidhistory': props.get('sidhistory', []),
                })
            
            # Kerberoastable
            if props.get('hasspn', False) and props.get('enabled', True):
                kerberoastable.append(name)
            
            # AS-REP Roastable
            if props.get('dontreqpreauth', False):
                dont_preauth.append(name)
            
            # Unconstrained delegation
            if props.get('unconstraineddelegation', False):
                unconstraineddelegation.append(name)
            
            # Dangerous ACEs on this user
            for ace in aces:
                right = ace.get('RightName', '')
                princ = ace.get('PrincipalSID', '')
                ptype = ace.get('PrincipalType', '')
                if right in ['GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite', 'ForceChangePassword', 'AddMember']:
                    all_aces[name].append({
                        'right': right,
                        'principal': princ,
                        'ptype': ptype
                    })

    # Print kerberoastable
    print(f"\n--- Kerberoastable Users ({len(kerberoastable)}) ---")
    for u in kerberoastable:
        print(f"  {u}")
    
    # Print AS-REP
    print(f"\n--- AS-REP Roastable ({len(dont_preauth)}) ---")
    for u in dont_preauth:
        print(f"  {u}")
    
    # Print unconstrained delegation
    print(f"\n--- Unconstrained Delegation Users ({len(unconstraineddelegation)}) ---")
    for u in unconstraineddelegation:
        print(f"  {u}")

    # Print admin users with interesting properties
    print(f"\n--- Admin Accounts (adminCount=1) ---")
    print(f"  Total: {len(admin_users)}")
    print(f"\n  Enabled admins with SPNs (Kerberoastable):")
    for u in admin_users:
        if u['hasspn'] and u.get('enabled', True):
            print(f"    {u['name']} | Desc: {u['description'][:60]}")
    
    print(f"\n  Admin accounts with SID History:")
    for u in admin_users:
        if u['sidhistory']:
            print(f"    {u['name']} | SIDHistory: {u['sidhistory']}")
    
    print(f"\n  Admin accounts with unconstrained delegation:")
    for u in admin_users:
        if u['unconstraineddelegation']:
            print(f"    {u['name']}")

    # Analyze groups for DA membership paths
    print("\n" + "="*60)
    print("GROUP ANALYSIS - DOMAIN ADMIN PATHS")
    print("="*60)
    
    da_group = None
    ea_group = None
    interesting_groups = {}
    
    for f in files:
        if 'groups' not in f:
            continue
        print(f"  [*] Processing {f}...")
        data = load_json_from_zip(zf, f)
        if not data or 'data' not in data:
            continue
        
        for group in data['data']:
            props = group.get('Properties', {})
            name = props.get('name', 'UNKNOWN')
            members = group.get('Members', [])
            aces = group.get('Aces', [])
            
            name_upper = name.upper()
            if 'DOMAIN ADMINS' in name_upper:
                da_group = group
                print(f"\n  [!] DOMAIN ADMINS: {len(members)} members")
                for m in members:
                    print(f"    {m.get('ObjectType','')}: {m.get('ObjectIdentifier','')}")
            
            if 'ENTERPRISE ADMINS' in name_upper:
                ea_group = group
                print(f"\n  [!] ENTERPRISE ADMINS: {len(members)} members")
                for m in members:
                    print(f"    {m.get('ObjectType','')}: {m.get('ObjectIdentifier','')}")
            
            if any(x in name_upper for x in ['ADMINISTRATORS', 'ACCOUNT OPERATORS', 'BACKUP OPERATORS', 'SERVER OPERATORS', 'DNSADMINS', 'EXCHANGE']):
                interesting_groups[name] = len(members)
            
            # Check for dangerous ACEs on groups
            for ace in aces:
                right = ace.get('RightName', '')
                if right in ['GenericAll', 'WriteDacl', 'WriteOwner', 'AddMember', 'GenericWrite']:
                    all_aces[f"GROUP:{name}"].append({
                        'right': right,
                        'principal': ace.get('PrincipalSID', ''),
                        'ptype': ace.get('PrincipalType', '')
                    })
    
    print(f"\n  Interesting Groups:")
    for gname, count in sorted(interesting_groups.items(), key=lambda x: x[1], reverse=True)[:20]:
        print(f"    {gname}: {count} members")

    # Print dangerous ACEs
    print("\n" + "="*60)
    print("DANGEROUS ACE RELATIONSHIPS")
    print("="*60)
    
    dangerous_count = 0
    for target, aces in all_aces.items():
        for ace in aces:
            if ace['right'] in ['GenericAll', 'WriteDacl', 'WriteOwner', 'ForceChangePassword', 'AddMember']:
                if dangerous_count < 50:
                    print(f"  {ace['ptype']}:{ace['principal']} --[{ace['right']}]--> {target}")
                dangerous_count += 1
    print(f"\n  Total dangerous ACE relationships: {dangerous_count}")

    # Analyze computers
    print("\n" + "="*60)
    print("COMPUTER ANALYSIS")
    print("="*60)
    
    dc_count = 0
    unconstrained_computers = []
    laps_computers = []
    
    for f in files:
        if 'computers' not in f:
            continue
        print(f"  [*] Processing {f}...")
        data = load_json_from_zip(zf, f)
        if not data or 'data' not in data:
            continue
        
        for comp in data['data']:
            props = comp.get('Properties', {})
            name = props.get('name', 'UNKNOWN')
            
            if props.get('isdc', False):
                dc_count += 1
                os_name = props.get('operatingsystem', 'N/A')
                print(f"  [DC] {name} | OS: {os_name}")
            
            if props.get('unconstraineddelegation', False) and not props.get('isdc', False):
                unconstrained_computers.append(name)
            
            if props.get('haslaps', False):
                laps_computers.append(name)
    
    print(f"\n  Domain Controllers: {dc_count}")
    print(f"  Non-DC Unconstrained Delegation: {len(unconstrained_computers)}")
    for c in unconstrained_computers[:10]:
        print(f"    {c}")
    print(f"  LAPS Enabled: {len(laps_computers)}")

    # GPO Analysis
    print("\n" + "="*60)
    print("GPO ANALYSIS")
    print("="*60)
    
    gpo_count = 0
    for f in files:
        if 'gpos' not in f:
            continue
        data = load_json_from_zip(zf, f)
        if not data or 'data' not in data:
            continue
        gpo_count += len(data['data'])
        
        for gpo in data['data'][:5]:
            props = gpo.get('Properties', {})
            aces = gpo.get('Aces', [])
            name = props.get('name', 'N/A')
            for ace in aces:
                right = ace.get('RightName', '')
                if right in ['GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite']:
                    print(f"  [!] {ace.get('PrincipalSID','')} --[{right}]--> GPO:{name}")
    
    print(f"  Total GPOs: {gpo_count}")

    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"  Admin accounts (adminCount=1): {len(admin_users)}")
    print(f"  Kerberoastable users: {len(kerberoastable)}")
    print(f"  AS-REP Roastable: {len(dont_preauth)}")
    print(f"  Unconstrained delegation (users): {len(unconstraineddelegation)}")
    print(f"  Unconstrained delegation (computers, non-DC): {len(unconstrained_computers)}")
    print(f"  Dangerous ACE relationships: {dangerous_count}")
    print(f"  Domain Controllers: {dc_count}")
    print(f"  GPOs: {gpo_count}")
    
    print("\n[*] Done.")

if __name__ == '__main__':
    main()
