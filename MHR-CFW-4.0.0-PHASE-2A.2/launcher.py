#!/usr/bin/env python3
"""MHR CFW 3.0 Windows launcher: Python control plane for MHR + sing-box TUN."""
from __future__ import annotations
import ctypes, json, os, socket, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / 'config.json'
MAIN = ROOT / 'main.py'
STATE = ROOT / 'runtime' / 'proxy_state.json'
HTTP_HOST, SOCKS_HOST = '127.0.0.1', '127.0.0.1'
DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT = 8085, 10808

def configured_ports():
    cfg = load_config() or {}
    return int(cfg.get('listen_port', DEFAULT_HTTP_PORT)), int(cfg.get('socks5_port', DEFAULT_SOCKS_PORT))


def is_windows() -> bool:
    return os.name == 'nt'


def is_admin() -> bool:
    if not is_windows(): return False
    try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception: return False


def banner():
    os.system('cls' if is_windows() else 'clear')
    print('=' * 64)
    print(' MHR CFW 3.0.0 | Windows 11 | Python Edition')
    print(' Browser proxy + optional sing-box TUN/DNS sidecar')
    print('=' * 64)


def load_config():
    if not CONFIG.exists(): return None
    try: return json.loads(CONFIG.read_text(encoding='utf-8'))
    except Exception as exc:
        print(f'[ERROR] config.json is invalid: {exc}')
        return None


def config_ready():
    cfg = load_config()
    if not cfg: return False
    required = ['auth_key']
    missing = [k for k in required if not cfg.get(k)]
    if cfg.get('auth_key') in ('CHANGE_ME_TO_A_STRONG_SECRET', 'REPLACE_ME', 'YOUR_SECRET'):
        missing.append('auth_key (placeholder)')
    sid = cfg.get('script_ids') or cfg.get('script_id')
    if not sid or sid == 'YOUR_APPS_SCRIPT_DEPLOYMENT_ID': missing.append('script_id')
    if missing:
        print('[SETUP REQUIRED] Missing or placeholder values: ' + ', '.join(missing))
        print('Run the setup wizard and deploy your own Apps Script + Worker first.')
        return False
    return True


def port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.4): return True
    except OSError: return False


def start_mhr():
    if not config_ready(): return None
    http_port, socks_port = configured_ports()
    if port_open(HTTP_HOST, http_port):
        print('[INFO] MHR HTTP proxy already appears to be listening.')
        return 'existing'
    cmd = [sys.executable, str(MAIN), '--no-cert-check']
    proc = subprocess.Popen(cmd, cwd=str(ROOT), creationflags=getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0))
    deadline = time.time() + 20
    while time.time() < deadline:
        if proc.poll() is not None:
            print(f'[ERROR] MHR exited early (code {proc.returncode}).')
            return None
        if port_open(HTTP_HOST, http_port):
            print(f'[OK] HTTP proxy:  http://{HTTP_HOST}:{http_port}')
            if port_open(SOCKS_HOST, socks_port): print(f'[OK] SOCKS5 proxy: socks5://{SOCKS_HOST}:{socks_port}')
            return proc
        time.sleep(0.25)
    print('[ERROR] MHR did not open the expected port. Check config.json and logs.')
    proc.terminate()
    return None


def notify_proxy_change():
    if not is_windows(): return
    try:
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        INTERNET_OPTION_REFRESH = 37
        ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        ctypes.windll.Wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception: pass


def set_windows_proxy(enable: bool):
    if not is_windows():
        print('[ERROR] Windows proxy management is only available on Windows.')
        return False
    import winreg
    key_path = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        if enable:
            # Save the exact prior values once, so they can be restored later.
            if not STATE.exists():
                previous = {}
                for name in ('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect'):
                    try: previous[name] = winreg.QueryValueEx(key, name)
                    except FileNotFoundError: previous[name] = None
                STATE.parent.mkdir(parents=True, exist_ok=True)
                STATE.write_text(json.dumps(previous, indent=2), encoding='utf-8')
            winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
            http_port, _ = configured_ports()
            winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, f'http={HTTP_HOST}:{http_port};https={HTTP_HOST}:{http_port}')
            winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, '<local>;localhost;127.*;10.*;192.168.*')
            try: winreg.DeleteValue(key, 'AutoConfigURL')
            except FileNotFoundError: pass
            print('[OK] Windows user proxy enabled for HTTP/HTTPS.')
        else:
            if STATE.exists():
                previous = json.loads(STATE.read_text(encoding='utf-8'))
                for name, item in previous.items():
                    try:
                        if item is None: winreg.DeleteValue(key, name)
                        else: winreg.SetValueEx(key, name, 0, item[1], item[0])
                    except FileNotFoundError: pass
                STATE.unlink(missing_ok=True)
            else:
                print('[INFO] No saved MHR proxy snapshot found; leaving current Windows proxy settings unchanged.')
                return True
            print('[OK] Previous Windows proxy settings restored.')
    notify_proxy_change()
    return True


def stop_process(proc):
    if proc is None or proc == 'existing': return
    try:
        proc.terminate(); proc.wait(timeout=8)
    except Exception:
        try: proc.kill()
        except Exception: pass


def run_browser_mode():
    proc = start_mhr()
    if proc is None: return
    if proc == 'existing':
        print('[INFO] Existing MHR process will not be stopped by this launcher.')
    set_windows_proxy(True)
    print('\nBrowser proxy is active. Press Ctrl+C to stop this session and restore settings.')
    try:
        while True:
            if proc not in (None, 'existing') and proc.poll() is not None:
                print('[ERROR] MHR process stopped unexpectedly.'); break
            time.sleep(1)
    except KeyboardInterrupt:
        print('\n[INFO] Stopping MHR...')
    finally:
        set_windows_proxy(False)
        stop_process(proc)
        print('[OK] Session ended; previous proxy settings restored.')


def run_tun_mode():
    if not is_admin():
        print('[ADMIN REQUIRED] Close this window, right-click run.bat and choose Run as administrator.')
        input('Press Enter to return...'); return
    cfg = load_config() or {}
    if not cfg.get('socks5_enabled', True):
        print('[SETUP REQUIRED] Enable SOCKS5 in setup.py; TUN uses the local SOCKS5 TCP CONNECT listener.')
        input('Press Enter to return...'); return
    proc = start_mhr()
    if proc is None: return
    _, socks_port = configured_ports()
    if not port_open(SOCKS_HOST, socks_port):
        print('[ERROR] MHR SOCKS5 listener is not available; TUN cannot start.')
        stop_process(proc); input('Press Enter to return...'); return
    try:
        from singbox_manager import ensure_sing_box, write_tun_config
        exe = ensure_sing_box(ROOT)
        if not exe:
            print('[ERROR] Could not install/verify official sing-box core.'); return
        _, socks_port = configured_ports()
        cfg_path = write_tun_config(ROOT, socks_port=socks_port, python_executable=sys.executable)
        check = subprocess.run([str(exe), 'check', '-c', str(cfg_path)], cwd=str(ROOT))
        if check.returncode != 0:
            print('[ERROR] sing-box rejected the generated TUN configuration.'); return
        print('[INFO] Starting TUN. TCP and DNS use MHR; non-DNS UDP is rejected so QUIC-capable browsers should fall back to TCP.')
        print('[INFO] This mode routes system traffic, not only browsers. Press Ctrl+C to stop.')
        tun = subprocess.Popen([str(exe), 'run', '-c', str(cfg_path)], cwd=str(ROOT))
        try:
            while tun.poll() is None:
                if proc not in ('existing', None) and proc.poll() is not None:
                    print('[ERROR] MHR stopped; stopping TUN to prevent direct fallback.'); break
                time.sleep(1)
        except KeyboardInterrupt: print('\n[INFO] Stopping TUN...')
        finally: stop_process(tun)
    except Exception as exc:
        print(f'[ERROR] TUN startup failed: {exc}')
    finally:
        stop_process(proc)


def install_ca(remove=False):
    action = '--uninstall-cert' if remove else '--install-cert'
    print('[INFO] This changes the Windows trusted-root certificate store.' if not remove else '[INFO] Removing MHR CA from trusted stores.')
    if not remove:
        answer = input('Only continue if you trust this local proxy. Install a new local CA? [y/N]: ').strip().lower()
        if answer not in ('y','yes'): return
    subprocess.call([sys.executable, str(MAIN), action], cwd=str(ROOT))
    input('Press Enter to continue...')


def diagnostics():
    print('Platform:', sys.platform)
    print('Python:', sys.version.split()[0])
    print('Config:', 'present' if CONFIG.exists() else 'missing')
    cfg = load_config()
    if cfg:
        print('HTTP bind:', cfg.get('listen_host'), cfg.get('listen_port'))
        print('SOCKS5 bind:', cfg.get('listen_host'), cfg.get('socks5_port'), '(UDP ASSOCIATE is not implemented by MHR 2.x)')
        print('LAN sharing:', cfg.get('lan_sharing', False))
        print('Relay credentials:', 'configured' if cfg.get('auth_key') and cfg.get('auth_key') != 'CHANGE_ME_TO_A_STRONG_SECRET' else 'not configured')
    hp, sp = configured_ports()
    print('HTTP port available:', not port_open(HTTP_HOST, hp))
    print('SOCKS port available:', not port_open(SOCKS_HOST, sp))
    print('Admin:', is_admin())
    print('TUN core:', 'installed' if (ROOT/'runtime'/'sing-box'/'sing-box.exe').exists() else 'download on first TUN start')
    input('\nPress Enter to continue...')


def main():
    if not is_windows():
        print('This package is designed for Windows 11. The MHR Python core may run elsewhere, but this manager is Windows-specific.')
        return 2
    while True:
        banner()
        print(' 1) Start MHR + enable Windows browser proxy (recommended)')
        print(' 2) Configure relay (setup wizard)')
        print(' 3) Install fresh local CA (optional; explicit consent)')
        print(' 4) Remove MHR local CA')
        print(' 5) Start TUN mode (administrator; optional sing-box download)')
        print(' 6) Restore/disable Windows proxy')
        print(' 7) Diagnostics')
        print(' 0) Exit')
        choice = input('\nSelect: ').strip()
        if choice == '1': run_browser_mode()
        elif choice == '2': subprocess.call([sys.executable, str(ROOT/'setup.py')], cwd=str(ROOT)); input('Press Enter...')
        elif choice == '3': install_ca(False)
        elif choice == '4': install_ca(True)
        elif choice == '5': run_tun_mode()
        elif choice == '6': set_windows_proxy(False); input('Press Enter...')
        elif choice == '7': diagnostics()
        elif choice == '0': return 0

if __name__ == '__main__': raise SystemExit(main())
