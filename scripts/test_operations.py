import importlib.util,pathlib,tempfile,unittest

def load(name):
 spec=importlib.util.spec_from_file_location(name,pathlib.Path(__file__).with_name(name+'.py'))
 module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
class OperationsTest(unittest.TestCase):
 def test_histogram_empty_and_tail(self):
  m=load('observe')
  self.assertIsNone(m.percentile({},.99))
  self.assertEqual(m.percentile({1:95,200:4,60001:1},.95),1)
  self.assertEqual(m.percentile({1:95,200:4,60001:1},.99),200)
 def test_atomic_replacement_preserves_backup(self):
  m=load('mygotunnelctl')
  with tempfile.TemporaryDirectory() as d:
   src=pathlib.Path(d)/'new'; dst=pathlib.Path(d)/'live'
   src.write_bytes(b'new'); dst.write_bytes(b'old')
   m.atomic(src,dst)
   self.assertEqual(dst.read_bytes(),b'new'); self.assertEqual(src.read_bytes(),b'new')
   self.assertEqual(dst.stat().st_mode&0o777,0o755)
if __name__=='__main__': unittest.main()

class ObservationIntegrationTest(unittest.TestCase):
 def test_real_text_log_aggregation(self):
  import json,sys
  from unittest import mock
  m=load('observe')
  with tempfile.TemporaryDirectory() as d:
   dest=pathlib.Path(d)/'observation'
   logs=[{'__CURSOR':'a','MESSAGE':'2026-10-16 08:41:32.186 INFO C ready example.invalid:443 id=abc-1 total=148.941ms'},
         {'__CURSOR':'b','MESSAGE':'2026-10-16 08:41:33.186 INFO C failed id=abc-2 stage=control'},
         {'__CURSOR':'c','MESSAGE':'2026-10-16 08:41:34.186 INFO C failed id=abc-1 stage=relay'},
         {'__CURSOR':'d','MESSAGE':'2026-10-16 08:41:35.186 INFO C stats active=11/1024 setup=0/128 idle=10/16 rejected=0'}]
   def fake(*args):
    if args[0]=='systemctl': return 'MainPID=0\nNRestarts=0\nActiveState=active\nInvocationID=test\n'
    return '\n'.join(json.dumps(x) for x in logs)
   with mock.patch.object(sys,'argv',['observe','--role','client','--output',str(dest),'--hours','0.000000001']),mock.patch.object(m,'command',side_effect=fake): m.main()
   summary=json.loads((dest/'summary.json').read_text())
   self.assertEqual(summary['ready'],1); self.assertEqual(summary['setup_failed'],1)
   self.assertEqual(summary['relay_failed'],1); self.assertEqual(summary['p99_setup_ms'],149)
   self.assertEqual(summary['resources']['active'],11); self.assertTrue(summary['complete'])
