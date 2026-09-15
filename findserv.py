#!/usr/bin/env python3
"""Find Windows Servers and test admin access - parallel, fast"""
import asyncio, sys, os, subprocess, socket
from concurrent.futures import ThreadPoolExecutor, as_completed

async def find_servers(url, modern_only=True):
    from msldap.commons.factory import LDAPConnectionFactory
    f = LDAPConnectionFactory.from_url(url)
    c = f.get_client()
    await c.connect()
    
    servers = []
    if modern_only:
        filt = '(&(objectClass=computer)(|(operatingSystem=*Server 2016*)(operatingSystem=*Server 2019*)(operatingSystem=*Server 2022*)(operatingSystem=*Server 2025*))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))'
    else:
        filt = '(&(objectClass=computer)(operatingSystem=*Server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))'
    
    async for entry, err in c.pagedsearch(filt, ['dNSHostName', 'operatingSystem', 'sAMAccountName']):
        if err:
            continue
        if entry and 'attributes' in entry:
            attrs = entry['attributes']
            dns = attrs.get('dNSHostName') or ''
            os_name = attrs.get('operatingSystem') or ''
            sam = attrs.get('sAMAccountName') or ''
            if dns:
                servers.append({'dns': dns, 'os': os_name, 'sam': sam})
    return servers

async def find_wsus_sccm(url):
    from msldap.commons.factory import LDAPConnectionFactory
    f = LDAPConnectionFactory.from_url(url)
    c = f.get_client()
    await c.connect()
    results = []
    for pattern in ['*wsus*', '*sccm*', '*mecm*', '*patch*', '*deploy*', '*wuda*']:
        async for entry, err in c.pagedsearch(f'(&(objectClass=computer)(cn={pattern}))', ['dNSHostName', 'operatingSystem']):
            if err:
                continue
            if entry and 'attributes' in entry:
                dns = entry['attributes'].get('dNSHostName') or ''
                os_name = entry['attributes'].get('operatingSystem') or ''
                if dns and dns not in [r['dns'] for r in results]:
                    results.append({'dns': dns, 'os': os_name})
    return results

def is_alive(host, port=445, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except:
        return False

def test_admin(host, user, pwd, domain):
    # First check if port 445 is open
    if not is_alive(host):
        return 'OFFLINE'
    try:
        subprocess.run(['net', 'use', f'\\\\{host}\\IPC$', '/delete', '/y'],
            capture_output=True, timeout=3)
    except:
        pass
    try:
        r = subprocess.run(
            ['net', 'use', f'\\\\{host}\\IPC$', f'/user:{domain}\\{user}', pwd],
            capture_output=True, text=True, timeout=5
        )
        if 'successfully' not in r.stdout.lower():
            return 'DENIED'
        # Try ADMIN$
        subprocess.run(['net', 'use', f'\\\\{host}\\IPC$', '/delete', '/y'],
            capture_output=True, timeout=3)
        r2 = subprocess.run(
            ['net', 'use', f'\\\\{host}\\ADMIN$', f'/user:{domain}\\{user}', pwd],
            capture_output=True, text=True, timeout=5
        )
        if 'successfully' in r2.stdout.lower():
            subprocess.run(['net', 'use', f'\\\\{host}\\ADMIN$', '/delete', '/y'],
                capture_output=True, timeout=3)
            return 'ADMIN$'
        # Try C$
        r3 = subprocess.run(
            ['net', 'use', f'\\\\{host}\\C$', f'/user:{domain}\\{user}', pwd],
            capture_output=True, text=True, timeout=5
        )
        if 'successfully' in r3.stdout.lower():
            subprocess.run(['net', 'use', f'\\\\{host}\\C$', '/delete', '/y'],
                capture_output=True, timeout=3)
            return 'C$'
        return 'IPC_ONLY'
    except:
        return 'TIMEOUT'

def test_worker(args):
    host, os_name, user, pwd, domain = args
    result = test_admin(host, user, pwd, domain)
    return host, os_name, result

def main():
    if len(sys.argv) < 2:
        print("Usage: findserv.py <ldap_url> [test_user] [test_pass] [test_domain] [--all]")
        print("  --all    Include older server OS (2003/2008/2012)")
        print("  Default: Only Server 2016/2019/2022/2025")
        sys.exit(1)
    
    url = sys.argv[1]
    test_user = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('-') else None
    test_pass = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith('-') else None
    test_domain = sys.argv[4] if len(sys.argv) > 4 and not sys.argv[4].startswith('-') else 'HO'
    modern_only = '--all' not in sys.argv

    # WSUS/SCCM first
    print("=" * 60)
    print("WSUS/SCCM/PATCH SERVERS")
    print("=" * 60)
    wsus = asyncio.run(find_wsus_sccm(url))
    if wsus:
        for s in wsus:
            if test_user and os.name == 'nt':
                result = test_admin(s['dns'], test_user, test_pass, test_domain)
                marker = " <-- ADMIN!" if result in ['ADMIN$', 'C$'] else ""
                print(f"  {s['dns']} | {s['os']} | {result}{marker}")
            else:
                print(f"  {s['dns']} | {s['os']}")
    else:
        print("  None found")

    # All servers
    os_label = "MODERN (2016+)" if modern_only else "ALL"
    print(f"\n{'='*60}")
    print(f"{os_label} WINDOWS SERVERS (non-DC)")
    print("=" * 60)
    servers = asyncio.run(find_servers(url, modern_only))
    print(f"  Total: {len(servers)}")
    
    if test_user and os.name == 'nt':
        print(f"\n  Testing admin access with {test_domain}\\{test_user}...")
        print(f"  Port check (2s) + admin test (5s) | 5 parallel threads")
        print(f"  Testing ALL {len(servers)} servers...\n")
        
        admin_hosts = []
        tested = 0
        tasks = [(s['dns'], s['os'], test_user, test_pass, test_domain) for s in servers]
        
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(test_worker, t): t for t in tasks}
            for future in as_completed(futures):
                host, os_name, result = future.result()
                tested += 1
                if result in ['ADMIN$', 'C$']:
                    print(f"  [!] {host} | {os_name} | {result} <-- ADMIN!")
                    admin_hosts.append(host)
                elif result == 'IPC_ONLY':
                    print(f"  [+] {host} | {os_name} | {result}")
                if tested % 50 == 0:
                    print(f"  --- Progress: {tested}/{len(servers)} tested, {len(admin_hosts)} admin found ---")
        
        print(f"\n{'='*60}")
        print(f"RESULTS: {tested} tested, {len(admin_hosts)} with ADMIN access")
        print("=" * 60)
        if admin_hosts:
            for h in admin_hosts:
                print(f"  [!] {h}")
        else:
            print("  No admin access found on tested servers")
    else:
        for s in servers[:50]:
            print(f"  {s['dns']} | {s['os']}")
        if len(servers) > 50:
            print(f"  ... and {len(servers)-50} more")

if __name__ == '__main__':
    main()
