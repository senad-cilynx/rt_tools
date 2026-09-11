#!/usr/bin/env python3
"""
Patches msldap bloodhound.py to fix:
1. KeyError when DN not in self.aces (6 locations)
2. TypeError bytes not JSON serializable in write_json_to_zip
"""
import os, sys

bhpath = os.path.join(os.environ.get('TEMP', '.'), 'python', 'Lib', 'site-packages', 'msldap', 'bloodhound.py')
if not os.path.exists(bhpath):
    print(f"[!] Not found: {bhpath}")
    sys.exit(1)

with open(bhpath, 'r', encoding='utf-8') as f:
    code = f.read()

patches = 0

# Patch 1: Fix write_json_to_zip bytes serialization
old_json = 'self.zipfile.writestr(filename, json.dumps(data))'
new_json = '''class _BHEncoder(json.JSONEncoder):
\t\t\tdef default(self, obj):
\t\t\t\tif isinstance(obj, bytes):
\t\t\t\t\ttry: return obj.decode('utf-8')
\t\t\t\t\texcept: return obj.hex()
\t\t\t\treturn super().default(obj)
\t\tself.zipfile.writestr(filename, json.dumps(data, cls=_BHEncoder))'''

if old_json in code:
    code = code.replace(old_json, new_json)
    patches += 1
    print("[+] Patch 1: Fixed bytes JSON serialization")

# Patch 2: Fix all KeyError locations for self.aces[] lookup
# Pattern: "\t\t\tmeta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]"
old_aces = "\t\t\tmeta, relations = self.aces[entry['Properties']['distinguishedname'].upper()]"
new_aces = """\t\t\t_dn_key = entry['Properties']['distinguishedname'].upper()
\t\t\tif _dn_key not in self.aces:
\t\t\t\tcontinue
\t\t\tmeta, relations = self.aces[_dn_key]"""

count = code.count(old_aces)
if count > 0:
    code = code.replace(old_aces, new_aces)
    patches += 1
    print(f"[+] Patch 2: Fixed KeyError in {count} locations")

with open(bhpath, 'w', encoding='utf-8') as f:
    f.write(code)

print(f"\n[*] {patches} patches applied to {bhpath}")
if patches > 0:
    print("[*] Re-run msldap-bloodhound now")
else:
    print("[!] No patches applied - patterns not found (maybe already patched or different version)")
