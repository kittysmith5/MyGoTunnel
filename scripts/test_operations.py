import importlib.util,pathlib,tempfile,unittest

def load(name):
 spec=importlib.util.spec_from_file_location(name,pathlib.Path(__file__).with_name(name+'.py'))
 module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
class OperationsTest(unittest.TestCase):
 def test_resource_availability_survives_text_and_json(self):
  import json
  m=load('observe')
  for message in [
   '2026-10-22 00:00:00.000 INFO C stats rss_bytes=0 rss_available=false fd_count=10 fd_available=true cpu_seconds=1.5 cpu_available=true',
   json.dumps(dict(msg='stats',rss_bytes=0,rss_available=False,fd_count=10,fd_available=True,cpu_seconds=1.5,cpu_available=True))]:
   a=m.Aggregator();a.consume(message)
   self.assertIs(a.resources['rss_available'],False);self.assertIs(a.resources['fd_available'],True)
   self.assertIs(a.resources['cpu_available'],True);self.assertEqual(a.resources['fd_count'],10)
 def test_udp_control_and_data_failures_keep_legacy_totals(self):
  import json
  m=load('observe');a=m.Aggregator()
  messages=[
   '2026-10-22 00:00:00.000 WARN C failed id=control stage=udp_control reason=reset udp_termination_scope=control',
   '2026-10-22 00:00:00.000 WARN S failed id=data stage=udp_tunnel_write reason=timeout udp_termination_scope=data',
   json.dumps(dict(msg='failed',connection_id='json',stage='udp_read',close_reason='error',transport='udp',udp_termination_scope='data')),
   '2026-10-22 00:00:00.000 WARN C failed id=old stage=udp_control reason=timeout',
   '2026-10-22 00:00:00.000 WARN C failed id=tcp stage=up reason=reset phase=copy']
  for message in messages:a.consume(message)
  row=a.snapshot()
  self.assertEqual(row['udp_control_failed'],2);self.assertEqual(row['udp_data_failed'],2)
  self.assertEqual(row['relay_failed'],5);self.assertEqual(row['setup_failed'],0)
  a.consume(messages[0]);self.assertEqual(a.snapshot(),row)
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

class SignatureTest(unittest.TestCase):
 def test_signature_authenticates_manifest_and_rejects_tampering(self):
  import base64,hashlib,json,pathlib,subprocess,tempfile
  m=load('mygotunnelctl')
  with tempfile.TemporaryDirectory() as d:
   d=pathlib.Path(d);key=d/'key.pem';pub=d/'pub.pem';der=d/'pub.der';payload=d/'payload';sig=d/'signature'
   subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-out',str(pub)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   subprocess.run(['openssl','pkey','-pubin','-in',str(pub),'-outform','DER','-out',str(der)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   signed=dict(version='v-test',commit='abc',built='now',key_id=hashlib.sha256(der.read_bytes()[-32:]).hexdigest()[:16],files={'client':'a'*64})
   payload.write_bytes(json.dumps(signed,sort_keys=True,separators=(',',':')).encode())
   subprocess.run(['openssl','pkeyutl','-sign','-inkey',str(key),'-rawin','-in',str(payload),'-out',str(sig)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   manifest=dict(signed,signature=base64.b64encode(sig.read_bytes()).decode())
   self.assertEqual(m.verify_manifest(manifest,pub)['commit'],'abc')
   manifest['files']['client']='b'*64
   with self.assertRaises(Exception):m.verify_manifest(manifest,pub)
   manifest=dict(signed,signature=base64.b64encode(sig.read_bytes()).decode());wrong=d/'wrong.pem'
   subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(wrong)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   with self.assertRaises(Exception):m.verify_manifest(manifest,wrong)

class CandidateSnapshotTest(unittest.TestCase):
 def fixture(self,root):
  import hashlib,json
  bundle=root/'bundle';stage=root/'private';bundle.mkdir();stage.mkdir(mode=0o700)
  payload=b'authenticated release binary'
  (bundle/'client-linux-arm64').write_bytes(payload)
  (bundle/'release-ed25519.pub.pem').write_bytes(b'public key')
  (bundle/'manifest.json').write_text('{}')
  signed=dict(commit='abc',version='v-test',files={'client-linux-arm64':hashlib.sha256(payload).hexdigest(),'release-ed25519.pub.pem':hashlib.sha256(b'public key').hexdigest()})
  return bundle,stage,signed,payload
 def test_bundle_change_after_snapshot_cannot_change_executed_file(self):
  import json
  from unittest import mock
  m=load('mygotunnelctl')
  with tempfile.TemporaryDirectory() as d:
   bundle,stage,signed,payload=self.fixture(pathlib.Path(d)); original=m.snapshot_regular
   def copy_then_change(source,destination):
    original(source,destination);source.write_bytes(b'replaced after snapshot')
   def execute(path,*args):
    self.assertEqual(pathlib.Path(path).parent,stage)
    self.assertEqual(pathlib.Path(path).read_bytes(),payload)
    return json.dumps(dict(commit='abc',version='v-test'))
   with mock.patch.object(m,'verify_manifest',return_value=signed),mock.patch.object(m,'snapshot_regular',side_effect=copy_then_change),mock.patch.object(m,'run',side_effect=execute):
    candidate=m.prepare_upgrade(bundle,'client','arm64',stage)
   self.assertEqual(candidate.read_bytes(),payload)
   self.assertNotEqual((bundle/'client-linux-arm64').read_bytes(),payload)
 def test_unverified_candidate_is_never_executed(self):
  from unittest import mock
  m=load('mygotunnelctl')
  with tempfile.TemporaryDirectory() as d:
   bundle,stage,signed,_=self.fixture(pathlib.Path(d));(bundle/'client-linux-arm64').write_bytes(b'tampered')
   with mock.patch.object(m,'verify_manifest',return_value=signed),mock.patch.object(m,'run') as run:
    with self.assertRaises(RuntimeError):m.prepare_upgrade(bundle,'client','arm64',stage)
    run.assert_not_called()
 def test_symlinks_and_special_files_are_rejected(self):
  import os
  m=load('mygotunnelctl')
  with tempfile.TemporaryDirectory() as d:
   d=pathlib.Path(d);regular=d/'regular';regular.write_bytes(b'data')
   link=d/'symlink';link.symlink_to(regular);fifo=d/'fifo';os.mkfifo(fifo)
   for source in (link,fifo,d):
    with self.assertRaises((OSError,RuntimeError)):m.snapshot_regular(source,d/'candidate')

class ObservationCoverageTest(unittest.TestCase):
 def test_collection_error_and_final_window_are_not_hidden(self):
  import json,sys
  from unittest import mock
  m=load('observe');clock=[100.0];calls=[0];windows=[]
  def fake(*args):
   if args[0]=='systemctl':
    calls[0]+=1
    if calls[0]==1:raise RuntimeError('transient collection failure')
    return 'MainPID=0\nNRestarts=0\nActiveState=active\nInvocationID=test\n'
   windows.append(float(args[args.index('--until')+1][1:]))
   clock[0]+=3 # the command crosses the scheduled end on its first success
   return ''
  def advance(seconds):clock[0]+=seconds
  with tempfile.TemporaryDirectory() as d:
   dest=pathlib.Path(d)/'observe'
   args=['observe','--role','client','--output',str(dest),'--hours','0.0006','--interval','1']
   with mock.patch.object(sys,'argv',args),mock.patch.object(m,'command',side_effect=fake),mock.patch.object(m.time,'time',side_effect=lambda:clock[0]),mock.patch.object(m.time,'sleep',side_effect=advance):m.main()
   summary=json.loads((dest/'summary.json').read_text())
   self.assertTrue(summary['finished']);self.assertFalse(summary['complete']);self.assertFalse(summary['data_complete'])
   self.assertEqual(summary['collection_errors'],1)
   self.assertEqual(windows[-1],102.16);self.assertGreaterEqual(len(windows),2)
 def test_scoped_unit_and_persistent_coverage_loss(self):
  import json,sys
  from unittest import mock
  m=load('observe');clock=[100.0];batches=[0]
  logs=[{'__CURSOR':'a','MESSAGE':'2026-10-20 00:00:00.000 INFO C ready id=one total=100ms'},
        {'__CURSOR':'b','MESSAGE':'2026-10-20 00:00:01.000 WARN C failed id=one stage=down reason=closed phase=half_close'}]
  def fake(*args):
   if args[0]=='systemctl':
    self.assertIn('mygotunnel-client-61080.service',args)
    return 'MainPID=0\nNRestarts=0\nActiveState=active\nInvocationID=test\n'
   self.assertEqual(args[args.index('-u')+1],'mygotunnel-client-61080.service')
   batches[0]+=1
   return '\n'.join(json.dumps(x) for x in logs) if batches[0]==1 else ''
  def advance(seconds):clock[0]+=seconds
  with tempfile.TemporaryDirectory() as d:
   dest=pathlib.Path(d)/'observe'
   args=['observe','--role','client','--unit','mygotunnel-client-61080.service','--output',str(dest),'--hours','0.0006','--interval','1','--journal-batch-size','2']
   with mock.patch.object(sys,'argv',args),mock.patch.object(m,'command',side_effect=fake),mock.patch.object(m.time,'time',side_effect=lambda:clock[0]),mock.patch.object(m.time,'sleep',side_effect=advance):m.main()
   summary=json.loads((dest/'summary.json').read_text())
   self.assertTrue(summary['finished']);self.assertFalse(summary['complete']);self.assertFalse(summary['data_complete'])
   self.assertFalse(summary['journal_batch_limit_reached']);self.assertEqual(summary['journal_batches_limited'],1)
   self.assertEqual(summary['shutdown_failed'],1);self.assertEqual(summary['relay_failed'],0)
 def test_closed_history_does_not_evict_active_connection(self):
  m=load('observe');a=m.Aggregator(limit=2)
  a.consume('2026-10-20 00:00:00.000 INFO C ready id=long total=50ms')
  for i in range(10):
   a.consume('2026-10-20 00:00:00.000 INFO C ready id=short'+str(i)+' total=10ms')
   a.consume('2026-10-20 00:00:00.000 INFO C closed id=short'+str(i)+' reason=eof')
  a.consume('2026-10-20 00:00:00.000 WARN C failed id=long stage=down reason=reset phase=copy')
  self.assertEqual(a.relay_failed,1);self.assertEqual(a.setup_failed,0);self.assertEqual(a.tracking_gaps,0)
 def test_auth_failure_rate_is_separate_and_missing_ready_is_not_setup(self):
  m=load('observe');a=m.Aggregator()
  a.consume('2026-10-20 00:00:00.000 WARN S failed id=probe stage=auth reason=eof')
  a.consume('2026-10-20 00:00:00.000 WARN S failed id=already-active stage=up reason=timeout phase=copy')
  a.consume('2026-10-20 00:00:00.000 INFO S ready id=ok total=10ms')
  a.consume('2026-10-20 00:00:00.000 WARN S failed id=target stage=dial reason=dns_not_found')
  row=a.snapshot()
  self.assertEqual(row['auth_failed'],1);self.assertEqual(row['setup_failed'],2);self.assertEqual(row['relay_failed'],1)
  self.assertEqual(row['proxy_failure_rate'],0.5)

 def test_real_socks_auth_log_contract_separates_auth_and_request_failures(self):
  # The Go client test validates these exact fields against real handshakes.
  m=load('observe');a=m.Aggregator()
  fixture=pathlib.Path(__file__).resolve().parent.parent/'internal/logging/testdata/socks_auth_events.jsonl'
  for event in fixture.read_text().splitlines():a.consume(event)
  a.consume('2026-10-20 00:00:00.000 INFO C ready id=healthy total=10ms')
  row=a.snapshot()
  self.assertEqual(row['auth_failed'],4)
  self.assertEqual(row['setup_failed'],5)
  self.assertEqual(row['failure_rate'],5/6)
  self.assertEqual(row['proxy_failure_rate'],0.5)
  self.assertEqual(row['setup_failures_by_reason'],{'auth_rejected':1,'auth_limited':1,'auth_protocol':2,'error':1})
  # Compact logs must use the same classification and retain generic SOCKS errors.
  b=m.Aggregator()
  for index,reason in enumerate(('auth_rejected','auth_limited','auth_protocol','timeout','error')):
   b.consume('2026-10-20 00:00:00.000 WARN C failed id=sample'+str(index)+' stage=socks reason='+reason)
  self.assertEqual(b.snapshot()['auth_failed'],3)
  self.assertEqual(b.snapshot()['setup_failed'],5)

if __name__=='__main__': unittest.main()
