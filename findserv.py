#!/usr/bin/env python3
"""Find Windows Servers (non-DC) and test admin access"""
import asyncio, sys, os, subprocess

async def find_servers(url):
    from msldap.commons.factory import LDAPConnectionFactory
    f = LDAPConnectionFactory.from_url(url)
    c = f.get_client()
    await c.connect()
    
    servers = []
    # Search for Windows Server OS computers that are NOT DCs
    async for entry, err in c.pagedsearch(
        '(&(objectClass=computer)(operatingSystem=*Server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))',
        ['dNSHostName', 'operatingSystem', 'sAMAccountName', 'operatingSystemVersion']
    ):
        if err:
            continue
        if entry and 'attributes' in entry:
            attrs = entry['attributes']
            dns = attrs.get('dNSHostName') or ''
            os_name = attrs.get('operatingSystem') or ''
            sam = attrs.get('sAMAccountName') or ''
            ver = attrs.get('operatingSystemVersion') or ''
            if dns:
                servers.append({'dns': dns, 'os': os_name, 'sam': sam, 'ver': ver})
    
    return servers

async def find_wsus_sccm(url):
    from msldap.commons.factory import LDAPConnectionFactory
    f = LDAPConnectionFactory.from_url(url)
    c = f.get_client()
    await c.connect()
    
    results = []
    for pattern in ['*wsus*', '*sccm*', '*mecm*', '*patch*', '*deploy*', '*wuda*']:
        async for entry, err in c.pagedsearch(
            f'(&(objectClass=computer)(cn={pattern}))',
            ['dNSHostName', 'operatingSystem', 'sAMAccountName']
        ):
            if err:
                continue
            if entry and 'attributes' in entry:
                attrs = entry['attributes']
                dns = attrs.get('dNSHostName') or ''
                os_name = attrs.get('operatingSystem') or ''
                sam = attrs.get('sAMAccountName') or ''
                if dns and dns not in [r['dns'] for r in results]:
                    results.append({'dns': dns, 'os': os_name, 'sam': sam})
    return results

def test_admin(host, user, pwd, domain):
    """Test if we have admin access via net use"""
    try:
        # Clean previous connections
        subprocess.run(['net', 'use', f'\\\\{host}\\IPC$', '/delete', '/y'],
            capture_output=True, timeout=5)
    except:
        pass
    try:
        r = subprocess.run(
            ['net', 'use', f'\\\\{host}\\IPC$', f'/user:{domain}\\{user}', pwd],
            capture_output=True, text=True, timeout=10
        )
        if 'successfully' in r.stdout.lower():
            # Try ADMIN$
            subprocess.run(['net', 'use', f'\\\\{host}\\IPC$', '/delete', '/y'],
                capture_output=True, timeout=5)
            r2 = subprocess.run(
                ['net', 'use', f'\\\\{host}\\ADMIN$', f'/user:{domain}\\{user}', pwd],
                capture_output=True, text=True, timeout=10
            )
            if 'successfully' in r2.stdout.lower():
                subprocess.run(['net', 'use', f'\\\\{host}\\ADMIN$', '/delete', '/y'],
                    capture_output=True, timeout=5)
                return 'ADMIN'
            # Try C$
            r3 = subprocess.run(
                ['net', 'use', f'\\\\{host}\\C$', f'/user:{domain}\\{user}', pwd],
                capture_output=True, text=True, timeout=10
            )
            if 'successfully' in r3.stdout.lower():
                subprocess.run(['net', 'use', f'\\\\{host}\\C$', '/delete', '/y'],
                    capture_output=True, timeout=5)
                return 'C$'
            return 'IPC_ONLY'
        return 'DENIED'
    except:
        return 'TIMEOUT'

def main():
    if len(sys.argv) < 2:
        print("Usage: findserv.py <ldap_url> [test_user] [test_pass] [test_domain]")
        sys.exit(1)
    
    url = sys.argv[1]
    test_user = sys.argv[2] if len(sys.argv) > 2 else None
    test_pass = sys.argv[3] if len(sys.argv) > 3 else None
    test_domain = sys.argv[4] if len(sys.argv) > 4 else 'HO'

    # Find WSUS/SCCM servers first
    print("=" * 60)
    print("WSUS/SCCM/PATCH SERVERS")
    print("=" * 60)
    wsus = asyncio.run(find_wsus_sccm(url))
    if wsus:
        for s in wsus:
            print(f"  {s['dns']} | {s['os']}")
            if test_user and os.name == 'nt':
                result = test_admin(s['dns'], test_user, test_pass, test_domain)
                print(f"    -> {result}")
    else:
        print("  None found")

    # Find all Windows Servers
    print("\n" + "=" * 60)
    print("ALL WINDOWS SERVERS (non-DC)")
    print("=" * 60)
    servers = asyncio.run(find_servers(url))
    print(f"  Total: {len(servers)}")
    
    if test_user and os.name == 'nt':
        print(f"\n  Testing admin access with {test_domain}\\{test_user}...")
        print(f"  (Testing first 20 servers)")
        admin_hosts = []
        for s in servers[:20]:
            result = test_admin(s['dns'], test_user, test_pass, test_domain)
            marker = " <-- ADMIN!" if result in ['ADMIN', 'C$'] else ""
            print(f"  {s['dns']} | {s['os']} | {result}{marker}")
            if result in ['ADMIN', 'C$']:
                admin_hosts.append(s['dns'])
        
        if admin_hosts:
            print(f"\n  [!] ADMIN ACCESS ON {len(admin_hosts)} SERVERS:")
            for h in admin_hosts:
                print(f"    {h}")
    else:
        for s in servers[:30]:
            print(f"  {s['dns']} | {s['os']}")
        if len(servers) > 30:
            print(f"  ... and {len(servers)-30} more")

if __name__ == '__main__':
    main()
