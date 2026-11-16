"""Verified official sing-box downloader and conservative TUN config generator."""
from __future__ import annotations
import hashlib, json, os, platform, urllib.request, zipfile
from pathlib import Path

API = 'https://api.github.com/repos/SagerNet/sing-box/releases/latest'
USER_AGENT = 'MHR-CFW/3.0.0 (Windows TUN sidecar)'
PINNED_SHA256 = {
    ('v1.14.4', 'sing-box-1.14.4-windows-amd64.zip'): '99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df'
}


def _request(url):
    req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, 'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(req, timeout=45) as response: return response.read()


def ensure_sing_box(root: Path) -> Path | None:
    if platform.machine().lower() not in ('amd64', 'x86_64', 'x64'):
        raise RuntimeError('This first build supports Windows x64 only; ARM64 support is not yet verified.')
    target_dir = root/'runtime'/'sing-box'
    exe = target_dir/'sing-box.exe'
    if exe.exists(): return exe
    release = json.loads(_request(API).decode('utf-8'))
    if release.get('prerelease'):
        raise RuntimeError('GitHub latest endpoint unexpectedly returned a prerelease; refusing automatic install.')
    candidates = [a for a in release.get('assets', []) if a.get('name','').lower().endswith('.zip') and 'windows-amd64' in a.get('name','').lower()]
    if not candidates:
        raise RuntimeError('No official Windows amd64 ZIP asset found in the latest stable SagerNet/sing-box release.')
    asset = candidates[0]
    digest = asset.get('digest') or ''
    if not digest.startswith('sha256:'):
        pinned = PINNED_SHA256.get((release.get('tag_name',''), asset.get('name','')))
        if not pinned:
            raise RuntimeError('Release asset has no SHA-256 digest metadata and no pinned checksum; refusing an unverified binary download.')
        digest = 'sha256:' + pinned
    archive = target_dir/'sing-box-download.zip'
    target_dir.mkdir(parents=True, exist_ok=True)
    archive.write_bytes(_request(asset['browser_download_url']))
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual.lower() != digest.split(':',1)[1].lower():
        archive.unlink(missing_ok=True)
        raise RuntimeError('SHA-256 mismatch for sing-box archive; download rejected.')
    with zipfile.ZipFile(archive) as zf:
        members = [m for m in zf.namelist() if Path(m).name.lower() in ('sing-box.exe','wintun.dll')]
        if not any(Path(m).name.lower() == 'sing-box.exe' for m in members):
            raise RuntimeError('The verified release archive does not contain sing-box.exe.')
        for member in members:
            dest = target_dir/Path(member).name
            dest.write_bytes(zf.read(member))
    archive.unlink(missing_ok=True)
    if not exe.exists(): raise RuntimeError('sing-box.exe extraction failed.')
    print(f"[OK] Installed verified {release.get('tag_name','sing-box')} (SHA-256 checked).")
    return exe


def write_tun_config(root: Path, socks_port: int = 10808, python_executable: str | None = None) -> Path:
    # MHR SOCKS5 accepts TCP CONNECT only. Therefore generic UDP is deliberately
    # rejected; DNS is hijacked and sent as HTTPS/DoH through the MHR TCP proxy.
    config = {
      'log': {'level':'info','timestamp':True},
      'dns': {
        'servers': [{
          'type':'https','tag':'doh-via-mhr','server':'1.1.1.1','server_port':443,
          'path':'/dns-query','tls':{'enabled':True,'server_name':'cloudflare-dns.com'},
          'detour':'mhr-socks'
        }],
        'final':'doh-via-mhr','strategy':'prefer_ipv4'
      },
      'inbounds': [{
        'type':'tun','tag':'mhr-tun','interface_name':'MHR-TUN',
        'address':['172.19.0.1/30','fdfe:dcba:9876::1/126'],'mtu':1500,'auto_route':True,
        'strict_route':True,'stack':'gvisor','dns_mode':'hijack','dns_address':['172.19.0.2','fdfe:dcba:9876::2']
      }],
      'outbounds': [
        {'type':'socks','tag':'mhr-socks','server':'127.0.0.1','server_port':int(socks_port),'version':'5'},
        {'type':'direct','tag':'direct'}
      ],
      'route': {
        'auto_detect_interface':True,
        'rules': [
          {'process_path':[str(Path(python_executable).resolve())] if python_executable else ['python.exe'], 'action':'route','outbound':'direct'},
          {'protocol':'dns','action':'hijack-dns'},
          {'ip_is_private':True,'action':'route','outbound':'direct'},
          {'network':'udp','action':'reject'}
        ],
        'final':'mhr-socks'
      }
    }
    path = root/'runtime'/'sing-box'/'mhr-tun.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2), encoding='utf-8')
    return path
