import importlib.util,pathlib,tempfile,unittest

def load(name):
 spec=importlib.util.spec_from_file_location(name,pathlib.Path(__file__).with_name(name+'.py'))
 module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
class OperationsTest(unittest.TestCase):
 def test_https_ingress_stats_do_not_pollute_proxy_failures(self):
  import json
  m=load('observe')
  for message in [
   '2026-10-22 00:00:00.000 INFO S stats ingress_http_requests=50 ingress_auth_rejected=6 ingress_http_unparsed=4 ingress_pre_auth_active=2',
   json.dumps(dict(msg='stats',ingress_http_requests=50,ingress_auth_rejected=6,ingress_http_unparsed=4,ingress_pre_auth_active=2))]:
   a=m.Aggregator();a.consume(message)
   self.assertEqual(a.resources['ingress_http_requests'],50)
   self.assertEqual(a.resources['ingress_auth_rejected'],6)
   self.assertEqual(a.snapshot()['setup_failed'],0)
   self.assertEqual(a.snapshot()['latency_samples'],0)
   self.assertIsNone(a.snapshot()['proxy_failure_rate'])
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

class UpgradeTransactionFixture:
 def __init__(self,test,with_state=True):
  import contextlib,hashlib,os
  from unittest import mock
  self.test=test;self.directory=tempfile.TemporaryDirectory();test.addCleanup(self.directory.cleanup)
  self.base=pathlib.Path(self.directory.name);self.root=self.base/'releases';self.root.mkdir(mode=0o700)
  self.binary=self.base/'live';self.binary.write_bytes(b'version-one');self.binary.chmod(0o755)
  self.candidate=self.base/'new';self.candidate.write_bytes(b'version-two');self.candidate.chmod(0o700)
  self.config=self.base/'config.json';self.config.write_bytes(b'{"test":true}\n');self.config.chmod(0o600)
  self.running=self.base/'runtime';self.running.write_bytes(self.binary.read_bytes())
  self.state=self.root/'client.json';self.unit='mygotunnel-client.service';self.unit_text='unchanged unit'
  if with_state:
   prior=self.root/'client-older';prior.write_bytes(b'version-zero')
   self.state.write_text(__import__('json').dumps({'previous':str(prior),'sha256':hashlib.sha256(prior.read_bytes()).hexdigest()}))
  self.before_state=self.state.read_bytes() if with_state else None
  self.module=load('mygotunnelctl');self.module.ROOT=self.root
  self.stack=contextlib.ExitStack();test.addCleanup(self.stack.close)
  self.restart_calls=[];self.checks=[];self.real_digest=self.module.digest;self.active=True
  self.stack.enter_context(mock.patch.object(self.module,'run',side_effect=self.run))
  self.stack.enter_context(mock.patch.object(self.module,'check',side_effect=self.check))
  self.stack.enter_context(mock.patch.object(self.module,'digest',side_effect=self.digest))
  self.stack.enter_context(mock.patch.object(self.module.time,'sleep'))
 def digest(self,path):
  if str(path)=='/proc/123/exe':path=self.running
  return self.real_digest(path)
 def run(self,*args):
  if args[:2]==('systemctl','cat'):return self.unit_text
  if args[:2]==('systemctl','restart'):
   self.restart_calls.append(args[2]);self.running.write_bytes(self.binary.read_bytes());self.active=True;return ''
  if args[:2]==('systemctl','is-active'):
   if not self.active:raise __import__('subprocess').CalledProcessError(3,args)
   return 'active'
  if args[:2]==('systemctl','show'):return '123'
  raise AssertionError('unexpected administrative command')
 def check(self,binary,config,health=False):self.checks.append((pathlib.Path(binary).read_bytes(),health))
 def change(self):return self.module.change_release('client',self.binary,self.config,self.unit,self.state,self.candidate)
 def begin(self):return self.module.begin_transaction('client',self.binary,self.config,self.unit,self.candidate,self.state)
 def recover(self):return self.module.recover_transaction('client',self.binary,self.config,self.unit,self.state)
 def assert_old_restored(self):
  self.test.assertEqual(self.binary.read_bytes(),b'version-one');self.test.assertEqual(self.running.read_bytes(),b'version-one')
  self.test.assertEqual(self.state.read_bytes() if self.state.exists() else None,self.before_state)
  self.test.assertFalse(self.module.intent_path('client').exists())

class UpgradeTransactionTest(unittest.TestCase):
 def test_success_publishes_intent_before_replace_and_commits_rollback_state(self):
  import json,hashlib
  from unittest import mock
  f=UpgradeTransactionFixture(self);m=f.module;atomic=m.atomic
  def replace(source,destination):
   record=m.read_record(m.intent_path('client'))
   self.assertEqual(record['phase'],'prepared');self.assertEqual(f.binary.read_bytes(),b'version-one')
   self.assertTrue(pathlib.Path(record['recovery_binary']).exists())
   self.assertTrue(pathlib.Path(record['state_before_copy']).exists())
   return atomic(source,destination)
  with mock.patch.object(m,'atomic',side_effect=replace),mock.patch.object(m,'fsync_directory',wraps=m.fsync_directory) as sync:
   self.assertFalse(f.change())
  self.assertEqual(f.binary.read_bytes(),b'version-two');self.assertEqual(f.running.read_bytes(),b'version-two')
  state=json.loads(f.state.read_text());self.assertEqual(pathlib.Path(state['previous']).read_bytes(),b'version-one')
  self.assertEqual(state['sha256'],hashlib.sha256(b'version-one').hexdigest())
  self.assertFalse(m.intent_path('client').exists())
  self.assertFalse(list(f.base.glob('.mygotunnel-recovery-*')));self.assertFalse(list(f.root.glob('.client-state-before-*')))
  self.assertIn(mock.call(f.binary.parent),sync.call_args_list);self.assertIn(mock.call(f.root),sync.call_args_list)
  self.assertEqual(f.config.read_bytes(),b'{"test":true}\n');self.assertEqual(f.unit_text,'unchanged unit')

 def test_state_enospc_restores_previous_bytes_using_preallocated_files(self):
  import errno
  from unittest import mock
  f=UpgradeTransactionFixture(self);m=f.module;write=m.write_json
  def full(path,value):
   if path==f.state:raise OSError(errno.ENOSPC,'injected state filesystem full')
   return write(path,value)
  with mock.patch.object(m,'write_json',side_effect=full),mock.patch.object(m,'atomic',wraps=m.atomic) as copy:
   with self.assertRaises(OSError):f.change()
  self.assertEqual(copy.call_count,1) # Rollback uses a reserved rename, not a second allocation.
  f.assert_old_restored()

 def test_state_fsync_failure_after_rename_restores_exact_old_state(self):
  import errno
  from unittest import mock
  for with_state in (False,True):
   with self.subTest(with_state=with_state):
    f=UpgradeTransactionFixture(self,with_state);m=f.module;write=m.write_json
    def failed_sync(path,value):
     write(path,value)
     if path==f.state:raise OSError(errno.EIO,'injected state directory fsync failure')
    with mock.patch.object(m,'write_json',side_effect=failed_sync):
     with self.assertRaises(OSError):f.change()
    f.assert_old_restored()

 def test_commit_record_enospc_still_rolls_back_with_existing_prepared_intent(self):
  import errno
  from unittest import mock
  f=UpgradeTransactionFixture(self);m=f.module;write=m.write_json
  def full(path,value):
   if path==m.intent_path('client') and value['phase']=='committed':raise OSError(errno.ENOSPC,'injected commit marker full')
   return write(path,value)
  with mock.patch.object(m,'write_json',side_effect=full):
   with self.assertRaises(OSError):f.change()
  f.assert_old_restored()

 def test_failure_publishing_intent_never_replaces_or_restarts(self):
  import errno
  from unittest import mock
  f=UpgradeTransactionFixture(self);m=f.module
  with mock.patch.object(m,'write_json',side_effect=OSError(errno.ENOSPC,'injected intent full')):
   with self.assertRaises(OSError):f.change()
  f.assert_old_restored();self.assertEqual(f.restart_calls,[])
  self.assertFalse(list(f.base.glob('.mygotunnel-recovery-*')))

 def test_preflight_rejects_before_any_transaction_or_restart(self):
  from unittest import mock
  f=UpgradeTransactionFixture(self)
  with mock.patch.object(f.module,'check',side_effect=RuntimeError('configuration invalid')):
   with self.assertRaises(RuntimeError):f.change()
  f.assert_old_restored();self.assertEqual(f.restart_calls,[])

 def test_interrupted_after_replace_before_restart_is_recovered(self):
  import multiprocessing,os
  if 'fork' not in multiprocessing.get_all_start_methods():self.skipTest('Linux fork failure injection')
  f=UpgradeTransactionFixture(self);m=f.module
  def killed_controller():
   run=m.run
   def stop(*args):
    if args[:2]==('systemctl','restart'):os._exit(91)
    return run(*args)
   m.run=stop;f.change()
  child=multiprocessing.get_context('fork').Process(target=killed_controller)
  child.start();child.join(5)
  if child.is_alive():child.kill();child.join();self.fail('controller did not stop')
  self.assertEqual(child.exitcode,91);self.assertEqual(f.binary.read_bytes(),b'version-two')
  self.assertTrue(m.intent_path('client').exists());self.assertEqual(f.running.read_bytes(),b'version-one')
  self.assertEqual(f.recover(),'rolled_back');f.assert_old_restored()
  self.assertEqual(f.restart_calls,[]) # The old process never stopped; recovery avoids another outage.

 def test_interrupted_after_restart_before_state_commit_is_recovered(self):
  import multiprocessing,os
  if 'fork' not in multiprocessing.get_all_start_methods():self.skipTest('Linux fork failure injection')
  f=UpgradeTransactionFixture(self);m=f.module
  def killed_controller():
   write=m.write_json
   def stop(path,value):
    if path==f.state:os._exit(92)
    return write(path,value)
   m.write_json=stop;f.change()
  child=multiprocessing.get_context('fork').Process(target=killed_controller)
  child.start();child.join(5)
  if child.is_alive():child.kill();child.join();self.fail('controller did not stop')
  self.assertEqual(child.exitcode,92);self.assertEqual(f.running.read_bytes(),b'version-two')
  self.assertEqual(f.recover(),'rolled_back');f.assert_old_restored()
  self.assertEqual(f.restart_calls,[f.unit])

 def test_interrupted_after_commit_only_cleans_up_without_rolling_back(self):
  import multiprocessing,os
  if 'fork' not in multiprocessing.get_all_start_methods():self.skipTest('Linux fork failure injection')
  f=UpgradeTransactionFixture(self);m=f.module
  def killed_controller():
   m.cleanup_transaction=lambda record:os._exit(93)
   f.change()
  child=multiprocessing.get_context('fork').Process(target=killed_controller)
  child.start();child.join(5)
  if child.is_alive():child.kill();child.join();self.fail('controller did not stop')
  self.assertEqual(child.exitcode,93);self.assertEqual(m.read_record(m.intent_path('client'))['phase'],'committed')
  self.assertEqual(f.recover(),'committed');self.assertEqual(f.binary.read_bytes(),b'version-two')
  self.assertEqual(f.running.read_bytes(),b'version-two');self.assertEqual(f.restart_calls,[])
  self.assertFalse(m.intent_path('client').exists())

 def test_committed_recovery_restarts_the_committed_version_if_needed(self):
  from unittest import mock
  for process_state in ('stopped','stale-old-process'):
   with self.subTest(process_state=process_state):
    f=UpgradeTransactionFixture(self);m=f.module
    with mock.patch.object(m,'cleanup_transaction',side_effect=OSError('injected interrupted cleanup')):
     self.assertTrue(f.change())
    f.restart_calls.clear()
    if process_state=='stopped':f.active=False
    else:f.running.write_bytes(b'version-one')
    self.assertEqual(f.recover(),'committed')
    self.assertEqual(f.binary.read_bytes(),b'version-two');self.assertEqual(f.running.read_bytes(),b'version-two')
    self.assertEqual(f.restart_calls,[f.unit]);self.assertTrue(f.active)
    self.assertFalse(m.intent_path('client').exists())

 def test_committed_recovery_refuses_external_protected_file_changes(self):
  from unittest import mock
  for changed in ('config','unit'):
   with self.subTest(changed=changed):
    f=UpgradeTransactionFixture(self);m=f.module
    with mock.patch.object(m,'cleanup_transaction',side_effect=OSError('injected interrupted cleanup')):
     self.assertTrue(f.change())
    f.restart_calls.clear()
    if changed=='config':f.config.write_bytes(b'{"external_change":true}')
    else:f.unit_text='externally changed unit'
    f.active=False
    with self.assertRaises(m.RecoveryRequired):f.recover()
    self.assertEqual(f.restart_calls,[]);self.assertEqual(f.binary.read_bytes(),b'version-two')
    self.assertTrue(m.intent_path('client').exists())

 def test_committed_health_failure_remains_pending_without_downgrading(self):
  from unittest import mock
  f=UpgradeTransactionFixture(self);m=f.module
  with mock.patch.object(m,'cleanup_transaction',side_effect=OSError('injected interrupted cleanup')):
   self.assertTrue(f.change())
  f.restart_calls.clear()
  def unhealthy(binary,config,health=False):
   if health:raise RuntimeError('injected committed health failure')
  with mock.patch.object(m,'check',side_effect=unhealthy):
   with self.assertRaises(m.RecoveryRequired):f.recover()
  self.assertEqual(f.binary.read_bytes(),b'version-two');self.assertEqual(f.running.read_bytes(),b'version-two')
  self.assertEqual(m.read_record(m.intent_path('client'))['phase'],'committed')
  self.assertEqual(f.restart_calls,[f.unit])

 def test_unprivileged_status_does_not_claim_no_pending_recovery(self):
  from unittest import mock
  f=UpgradeTransactionFixture(self);m=f.module
  self.assertFalse(m.recovery_pending('client'))
  f.begin();self.assertTrue(m.recovery_pending('client'))
  with mock.patch.object(pathlib.Path,'lstat',side_effect=PermissionError('private release directory')):
   self.assertIsNone(m.recovery_pending('client'))

 def test_recovery_does_not_allocate_stage_or_continue_a_second_mutation(self):
  import io,json,sys,types
  from unittest import mock
  for action in ('recover','upgrade','rollback'):
   with self.subTest(action=action):
    f=UpgradeTransactionFixture(self);m=f.module;f.begin();m.atomic(f.candidate,f.binary)
    real_path=pathlib.Path
    def mapped_path(value):
     return {'/usr/local/bin/mygotunnel-client':f.binary,'/etc/mygotunnel/client.json':f.config}.get(str(value),real_path(value))
    output=io.StringIO()
    with mock.patch.object(m,'pathlib',types.SimpleNamespace(Path=mapped_path)),mock.patch.object(m.os,'geteuid',return_value=0),mock.patch.object(m,'ensure_release_directory'),mock.patch.object(m,'identity',return_value={'version':'test'}),mock.patch.object(m.tempfile,'TemporaryDirectory',side_effect=OSError('injected no free space for a new stage')),mock.patch.object(m,'prepare_upgrade') as prepare,mock.patch.object(sys,'argv',['ctl',action,'--role','client']),mock.patch.object(sys,'stdout',output):
     self.assertEqual(m.main(),0)
    result=json.loads(output.getvalue());self.assertEqual(result['action'],'recover');self.assertTrue(result['recovery_only'])
    self.assertEqual(result['recovered'],'rolled_back');self.assertEqual(result['requested_action'],action)
    self.assertFalse(prepare.called);f.assert_old_restored()

 def test_failed_rollback_keeps_intent_and_can_be_retried(self):
  from unittest import mock
  f=UpgradeTransactionFixture(self);m=f.module
  def unhealthy(binary,config,health=False):
   if health:raise RuntimeError('injected health failure')
  with mock.patch.object(m,'check',side_effect=unhealthy):
   with self.assertRaises(m.RecoveryRequired):f.change()
  self.assertTrue(m.intent_path('client').exists())
  self.assertEqual(f.recover(),'rolled_back');f.assert_old_restored()

 def test_recovery_preserves_external_config_changes_and_rejects_bad_paths(self):
  f=UpgradeTransactionFixture(self);m=f.module;record=f.begin();m.atomic(f.candidate,f.binary)
  f.config.write_bytes(b'{"external_change":true}')
  with self.assertRaises(m.RecoveryRequired):f.recover()
  self.assertEqual(f.config.read_bytes(),b'{"external_change":true}');self.assertEqual(f.binary.read_bytes(),b'version-two')
  f.config.write_bytes(b'{"test":true}\n');record['previous']=str(f.base/'outside-release-directory')
  m.write_json(m.intent_path('client'),record)
  with self.assertRaises(m.RecoveryRequired):f.recover()
  self.assertEqual(f.binary.read_bytes(),b'version-two');self.assertTrue(m.intent_path('client').exists())

 def test_setid_is_rejected_before_replacement(self):
  import stat
  from unittest import mock
  f=UpgradeTransactionFixture(self);m=f.module;f.binary.chmod(0o755|stat.S_ISUID)
  with mock.patch.object(m,'atomic') as replace:
   with self.assertRaises(m.FilePrivilegesUnsupported):f.change()
  self.assertFalse(replace.called)
  f.binary.chmod(0o755);f.assert_old_restored();self.assertEqual(f.restart_calls,[])

 def test_file_capability_preflight_is_covered_without_privilege(self):
  from unittest import mock
  f=UpgradeTransactionFixture(self);m=f.module
  with mock.patch.object(m.os,'getxattr',return_value=b'nonempty-capability',create=True),mock.patch.object(m,'atomic') as replace:
   with self.assertRaises(m.FilePrivilegesUnsupported):f.change()
  self.assertFalse(replace.called);f.assert_old_restored();self.assertEqual(f.restart_calls,[])

 def test_real_file_capabilities_survive_safe_refusal(self):
  import os,shutil,subprocess
  f=UpgradeTransactionFixture(self);m=f.module
  if not hasattr(os,'getxattr') or shutil.which('setcap') is None:self.skipTest('file capabilities unavailable')
  result=subprocess.run(['setcap','cap_net_bind_service=ep',str(f.binary)],capture_output=True)
  if result.returncode:self.skipTest('filesystem or user cannot set file capabilities')
  before=os.getxattr(f.binary,'security.capability')
  with self.assertRaises(m.FilePrivilegesUnsupported):f.change()
  self.assertEqual(os.getxattr(f.binary,'security.capability'),before)
  f.assert_old_restored();self.assertEqual(f.restart_calls,[])

if __name__=='__main__': unittest.main()
