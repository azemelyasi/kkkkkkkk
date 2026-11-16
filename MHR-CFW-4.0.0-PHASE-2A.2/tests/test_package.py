import json, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class PackageTests(unittest.TestCase):
 def test_example_config_is_local_only(self):
  cfg=json.loads((ROOT/'config.example.json').read_text(encoding='utf-8'))
  self.assertEqual(cfg['listen_host'],'127.0.0.1')
  self.assertFalse(cfg['lan_sharing'])
  self.assertEqual(cfg['listen_port'],8085)
  self.assertEqual(cfg['socks5_port'],10808)
 def test_no_live_config_or_ca_private_key(self):
  self.assertFalse((ROOT/'config.json').exists())
  self.assertFalse((ROOT/'ca'/'ca.key').exists())
 def test_tun_config_is_conservative(self):
  import sys
  sys.path.insert(0, str(ROOT))
  from singbox_manager import write_tun_config
  cfg=json.loads(write_tun_config(ROOT, socks_port=10808, python_executable='python.exe').read_text(encoding='utf-8'))
  self.assertEqual(cfg['inbounds'][0]['type'],'tun')
  self.assertTrue(cfg['inbounds'][0]['auto_route'])
  self.assertEqual(cfg['outbounds'][0]['server_port'],10808)
  self.assertEqual(cfg['route']['rules'][0]['action'],'route')
  self.assertEqual(cfg['route']['rules'][1]['action'],'hijack-dns')
  self.assertTrue(cfg['route']['rules'][2]['ip_is_private'])
  self.assertEqual(cfg['route']['rules'][3]['network'],'udp')
  self.assertEqual(cfg['route']['rules'][3]['action'],'reject')

 def test_windows_proxy_settings_are_restored(self):
  import sys, types, tempfile
  sys.path.insert(0, str(ROOT))
  import launcher
  class FakeKey:
   def __enter__(self): return self
   def __exit__(self,*a): return False
  registry={'ProxyEnable':(1,4),'ProxyServer':('old.proxy:1234',1),'ProxyOverride':('<local>',1),'AutoDetect':(1,4)}
  fake=types.SimpleNamespace(HKEY_CURRENT_USER=1,KEY_READ=2,KEY_WRITE=4,REG_DWORD=4,REG_SZ=1)
  fake.OpenKey=lambda *a: FakeKey()
  def query(key,name):
   if name not in registry: raise FileNotFoundError(name)
   return registry[name]
  fake.QueryValueEx=query
  fake.SetValueEx=lambda key,name,res,typ,value: registry.__setitem__(name,(value,typ))
  def delete(key,name):
   if name not in registry: raise FileNotFoundError(name)
   del registry[name]
  fake.DeleteValue=delete
  old_state=launcher.STATE
  with tempfile.TemporaryDirectory() as td:
   launcher.STATE=Path(td)/'proxy_state.json'
   sys.modules['winreg']=fake
   launcher.is_windows=lambda: True
   launcher.configured_ports=lambda: (8085,10808)
   launcher.set_windows_proxy(True)
   self.assertEqual(registry['ProxyEnable'][0],1)
   self.assertIn('127.0.0.1:8085',registry['ProxyServer'][0])
   launcher.set_windows_proxy(False)
   self.assertEqual(registry['ProxyServer'][0],'old.proxy:1234')
   self.assertEqual(registry['AutoDetect'][0],1)
   self.assertFalse(launcher.STATE.exists())
  launcher.STATE=old_state

 def test_scripts_are_placeholders(self):
  gs=(ROOT/'script'/'Code.gs').read_text(encoding='utf-8')
  # Phase 2A: secrets come from Script Properties, not hard-coded constants.
  self.assertIn('AUTH_KEY', gs)
  self.assertIn('PropertiesService', gs)
  self.assertIn('YOUR-WORKER-NAME', gs)
  self.assertNotIn('erfan' + 'elyasi1387', gs)
  self.assertNotIn('REPLACE_WITH_THE_SAME_RANDOM_SECRET_AS_CONFIG_JSON', gs)
  wj=(ROOT/'script'/'worker.js').read_text(encoding='utf-8')
  self.assertIn('AUTH_KEY', wj)
  self.assertIn('signed_envelope_required', wj)
if __name__=='__main__': unittest.main()
