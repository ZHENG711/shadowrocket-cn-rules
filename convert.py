import urllib.request, re, ipaddress
def get(u): return urllib.request.urlopen(u, timeout=60).read().decode('utf-8','ignore')
SORL='https://raw.githubusercontent.com/pluwen/china-domain-allowlist/main/allow-list.sorl'
CIDR='https://github.com/Loyalsoldier/clash-rules/releases/latest/download/cncidr.txt'
dom=set()
for l in get(SORL).splitlines():
    l=l.strip()
    if not l or l.startswith((';','[','#')): continue
    if re.fullmatch(r'[\d*]+(\.[\d*]+){3}', l): continue  # LAN IP wildcards, handled by existing rules
    d=l.lstrip('*').lstrip('.').lower()
    if re.fullmatch(r'[a-z0-9-]+(\.[a-z0-9-]+)*', d): dom.add(d)
out=['# Source: '+SORL, '# Converted for Shadowrocket']+[f'DOMAIN-SUFFIX,{d}' for d in sorted(dom)]
open('cn_domain.list','w').write('\n'.join(out)+'\n')
ips=[]
for l in get(CIDR).splitlines():
    m=re.search(r"'([^']+)'", l)
    if not m: continue
    n=ipaddress.ip_network(m.group(1), strict=False)
    ips.append(f"{'IP-CIDR' if n.version==4 else 'IP-CIDR6'},{n},no-resolve")
assert len(dom)>500 and len(ips)>3000
open('cn_cidr.list','w').write('\n'.join(['# Source: '+CIDR,'# Converted for Shadowrocket']+ips)+'\n')
print(len(dom), len(ips))
