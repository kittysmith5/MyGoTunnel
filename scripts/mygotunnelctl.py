#!/usr/bin/env python3
"""Local root-only upgrades using signed, private snapshots of release files."""
import argparse,base64,errno,fcntl,hashlib,json,os,pathlib,platform,socket,stat,subprocess,tempfile,time

TRUSTED_KEYS=pathlib.Path("/etc/mygotunnel/release-keys")
ROOT=pathlib.Path('/var/lib/mygotunnel/releases')
MAX_BINARY_BYTES=256*1024*1024
class RecoveryRequired(RuntimeError): pass
class FilePrivilegesUnsupported(RuntimeError): pass

def run(*args):
 return subprocess.check_output(args,text=True,stderr=subprocess.DEVNULL,timeout=45).strip()
def digest(p):
 h=hashlib.sha256()
 with open(p,'rb') as f:
  for data in iter(lambda:f.read(1024*1024),b''): h.update(data)
 return h.hexdigest()

def fsync_directory(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
 try: os.fsync(fd)
 finally: os.close(fd)

def require_plain_binary(path):
 info=path.lstat()
 if not stat.S_ISREG(info.st_mode): raise RuntimeError('binary must be a regular file')
 if info.st_mode&(stat.S_ISUID|stat.S_ISGID): raise FilePrivilegesUnsupported('set-id binaries require explicit deployment policy')
 if hasattr(os,'getxattr'):
  try: capability=os.getxattr(path,'security.capability',follow_symlinks=False)
  except OSError as error:
   if error.errno not in (errno.ENODATA,errno.ENOTSUP,getattr(errno,'ENOATTR',errno.ENODATA)): raise
  else:
   if capability: raise FilePrivilegesUnsupported('file capabilities require explicit deployment policy')
def snapshot_regular(source,destination):
 # Never execute the bundle path. Snapshot through one fd, reject symlinks and
 # special files, then authenticate these exact private bytes before execution.
 fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_size>MAX_BINARY_BYTES: raise RuntimeError('invalid candidate file')
  with os.fdopen(fd,'rb',closefd=False) as src,open(destination,'xb') as dst:
   total=0
   while True:
    data=src.read(1024*1024)
    if not data: break
    total+=len(data)
    if total>MAX_BINARY_BYTES: raise RuntimeError('candidate file too large')
    dst.write(data)
   dst.flush();os.fsync(dst.fileno())
  os.chmod(destination,0o700)
 finally: os.close(fd)

def stage_verified(source,stage,expected):
 candidate=stage/'candidate'
 snapshot_regular(source,candidate)
 if digest(candidate)!=expected: raise RuntimeError('candidate checksum mismatch')
 return candidate

def prepare_upgrade(bundle,role,arch,stage):
 manifest=json.loads((bundle/'manifest.json').read_text())
 signed=verify_manifest(manifest)
 name=role+'-linux-'+arch
 if digest(bundle/'release-ed25519.pub.pem')!=signed['files']['release-ed25519.pub.pem']: raise RuntimeError('bundle public key checksum mismatch')
 candidate=stage_verified(bundle/name,stage,signed['files'][name])
 info=json.loads(run(str(candidate),'-version'))
 if info['commit']!=signed['commit'] or info['version']!=signed['version']: raise RuntimeError('build identity mismatch')
 return candidate
def prepare_replacement(src,dst,prefix='.mygotunnel-'):
 require_plain_binary(src)
 if os.path.lexists(dst): require_plain_binary(dst)
 fd,tmp=tempfile.mkstemp(prefix=prefix,dir=dst.parent)
 try:
  with os.fdopen(fd,'wb') as f:
   source=os.open(src,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
   try:
    if not stat.S_ISREG(os.fstat(source).st_mode): raise RuntimeError('invalid replacement file')
    with os.fdopen(source,'rb',closefd=False) as r:
     total=0
     for data in iter(lambda:r.read(1024*1024),b''):
      total+=len(data)
      if total>MAX_BINARY_BYTES: raise RuntimeError('replacement file too large')
      f.write(data)
   finally: os.close(source)
   os.fchmod(f.fileno(),0o755)
   f.flush(); os.fsync(f.fileno())
  fsync_directory(dst.parent)
  return pathlib.Path(tmp)
 except BaseException:
  if os.path.exists(tmp): os.unlink(tmp)
  raise

def atomic(src,dst):
 tmp=prepare_replacement(src,dst)
 try:
  os.replace(tmp,dst); fsync_directory(dst.parent)
 finally:
  if tmp.exists(): tmp.unlink()

def write_json(path,value):
 fd,tmp=tempfile.mkstemp(prefix='.'+path.name+'-',dir=path.parent)
 try:
  with os.fdopen(fd,'w') as f:
   json.dump(value,f,sort_keys=True,separators=(',',':')); f.write('\n')
   f.flush(); os.fsync(f.fileno())
  os.replace(tmp,path); fsync_directory(path.parent)
 finally:
  if os.path.exists(tmp): os.unlink(tmp)
def verify_manifest(manifest,key_path=None):
 if not isinstance(manifest,dict) or not all(k in manifest for k in ('version','commit','built','key_id','files','signature')): raise RuntimeError('invalid signed manifest')
 signed={k:manifest[k] for k in ('version','commit','built','key_id','files')}
 with tempfile.TemporaryDirectory() as d:
  d=pathlib.Path(d); pub=d/'pub.der'; payload=d/'payload'; sig=d/'signature'
  candidates=[pathlib.Path(key_path)] if key_path else sorted(TRUSTED_KEYS.glob('*.pub.pem'))
  trusted=None
  for candidate in candidates:
   result=subprocess.run(['openssl','pkey','-pubin','-in',str(candidate),'-outform','DER','-out',str(pub)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   if result.returncode==0 and hashlib.sha256(pub.read_bytes()[-32:]).hexdigest()[:16]==manifest['key_id']:
    trusted=candidate;break
  if trusted is None: raise RuntimeError('untrusted signing key')
  payload.write_bytes(json.dumps(signed,sort_keys=True,separators=(',',':')).encode())
  signature=base64.b64decode(manifest['signature'],validate=True); sig.write_bytes(signature)
  subprocess.run(['openssl','pkeyutl','-verify','-pubin','-inkey',str(trusted),'-rawin','-in',str(payload),'-sigfile',str(sig)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 return signed

def identity(binary):
 try: return json.loads(run(str(binary),'-version'))
 except subprocess.CalledProcessError: return dict(version='legacy',commit='unknown')
def check(binary,config,health=False):
 if identity(binary)['version']!='legacy':
  return run(str(binary),'-config',config,'-health' if health else '-check-config')
 # Legacy rollback: configuration was preserved, verify its listener directly.
 cfg=json.loads(pathlib.Path(config).read_text())
 if health:
  addr=cfg.get('local_addr',cfg.get('listen_addr',':9001'))
  host,port=addr.rsplit(':',1); host=host.strip('[]')
  if host in ('','0.0.0.0','::'): host='127.0.0.1'
  with socket.create_connection((host,int(port)),timeout=3): pass
 return None

def unit_digest(unit): return hashlib.sha256(run('systemctl','cat',unit).encode()).hexdigest()

def validate_running(binary,config,unit,expected,config_hash,unit_hash):
 if digest(pathlib.Path(config))!=config_hash or unit_digest(unit)!=unit_hash: raise RecoveryRequired('protected files changed')
 if run('systemctl','is-active',unit)!='active': raise RuntimeError('service is not active')
 pid=run('systemctl','show','-p','MainPID','--value',unit)
 if not pid.isdecimal() or int(pid)==0: raise RuntimeError('service has no main process')
 if digest(pathlib.Path('/proc')/pid/'exe')!=expected or digest(binary)!=expected: raise RuntimeError('running executable mismatch')
 check(binary,config,health=True)

def ensure_running(binary,config,unit,expected,config_hash,unit_hash):
 try: validate_running(binary,config,unit,expected,config_hash,unit_hash)
 except RecoveryRequired: raise
 except Exception:
  run('systemctl','restart',unit)
  time.sleep(2)
  validate_running(binary,config,unit,expected,config_hash,unit_hash)

def read_record(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_size>65536: raise RecoveryRequired('invalid transaction record')
  with os.fdopen(fd,'rb',closefd=False) as source: data=source.read(65537)
  if len(data)>65536: raise RecoveryRequired('transaction record too large')
  return json.loads(data)
 finally: os.close(fd)

def intent_path(role): return ROOT/(role+'.intent.json')

def recovery_pending(role):
 try: intent_path(role).lstat()
 except FileNotFoundError: return False
 except PermissionError: return None
 return True

def validate_intent(record,role,binary,config,unit):
 try:
  if record['schema']!=1 or record['role']!=role or record['phase'] not in ('prepared','committed'): raise ValueError()
  if record['binary']!=str(binary) or record['config']!=str(config) or record['unit']!=unit: raise ValueError()
  for key in ('old_sha256','new_sha256','config_sha256','unit_sha256'):
   value=record[key]
   if not isinstance(value,str) or len(value)!=64 or any(c not in '0123456789abcdef' for c in value): raise ValueError()
  saved=pathlib.Path(record['previous'])
  if saved.parent!=ROOT or not saved.name.startswith(role+'-previous-'): raise ValueError()
  ready=pathlib.Path(record['recovery_binary'])
  if ready.parent!=binary.parent or not ready.name.startswith('.mygotunnel-recovery-'+role+'-'): raise ValueError()
  before=record['state_before_copy']; before_hash=record['state_before_sha256']
  if before is not None:
   before=pathlib.Path(before)
   if before.parent!=ROOT or not before.name.startswith('.'+role+'-state-before-'): raise ValueError()
   if not isinstance(before_hash,str) or len(before_hash)!=64 or any(c not in '0123456789abcdef' for c in before_hash): raise ValueError()
  elif before_hash is not None: raise ValueError()
  return record
 except (KeyError,TypeError,ValueError): raise RecoveryRequired('invalid transaction intent') from None

def cleanup_transaction(record):
 directories={ROOT}
 for key in ('recovery_binary','state_before_copy'):
  if record[key] is not None:
   path=pathlib.Path(record[key]); directories.add(path.parent)
   try: path.unlink()
   except FileNotFoundError: pass
 for directory in directories: fsync_directory(directory)
 try: intent_path(record['role']).unlink()
 except FileNotFoundError: pass
 fsync_directory(ROOT)

def begin_transaction(role,binary,config,unit,candidate,state):
 require_plain_binary(binary); require_plain_binary(candidate)
 config_hash=digest(pathlib.Path(config)); unit_hash=unit_digest(unit)
 check(candidate,config)
 if config_hash!=digest(pathlib.Path(config)) or unit_hash!=unit_digest(unit): raise RuntimeError('protected files changed during preflight')
 saved=ROOT/(role+'-previous-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+str(time.time_ns()))
 ready=None; before=None
 try:
  snapshot_regular(binary,saved); fsync_directory(ROOT)
  old_hash=digest(saved)
  # Reserve rollback bytes on the executable's own filesystem before changing
  # it. State ENOSPC can then roll back through rename, without another copy.
  ready=prepare_replacement(saved,binary,prefix='.mygotunnel-recovery-'+role+'-')
  if digest(ready)!=old_hash: raise RuntimeError('rollback reservation checksum mismatch')
  before_hash=None
  if os.path.lexists(state):
   before=ROOT/('.'+role+'-state-before-'+str(time.time_ns()))
   snapshot_regular(state,before); os.chmod(before,0o600); fsync_directory(ROOT)
   before_hash=digest(before)
  record=dict(schema=1,role=role,phase='prepared',binary=str(binary),config=str(config),unit=unit,previous=str(saved),old_sha256=old_hash,new_sha256=digest(candidate),recovery_binary=str(ready),state_before_copy=str(before) if before else None,state_before_sha256=before_hash,config_sha256=config_hash,unit_sha256=unit_hash)
  write_json(intent_path(role),record)
  return record
 except BaseException:
  # If publication or its fsync failed after rename, retain the intent and its
  # recovery files; a subsequent recover can safely inspect the durable state.
  if not intent_path(role).exists():
   for path in (saved,ready,before):
    if path is not None and path.exists(): path.unlink()
  raise

def restore_transaction(record,binary,config,unit,state):
 if digest(pathlib.Path(config))!=record['config_sha256'] or unit_digest(unit)!=record['unit_sha256']: raise RecoveryRequired('protected files changed; restore them before recovery')
 expected=record['old_sha256']; saved=pathlib.Path(record['previous'])
 require_plain_binary(saved); require_plain_binary(binary)
 if digest(saved)!=expected: raise RecoveryRequired('rollback backup checksum mismatch')
 current=digest(binary)
 if current not in (expected,record['new_sha256']): raise RecoveryRequired('installed binary changed outside transaction')
 ready=pathlib.Path(record['recovery_binary'])
 if current!=expected:
  if not ready.exists(): raise RecoveryRequired('rollback reservation is missing')
  require_plain_binary(ready)
  if digest(ready)!=expected: raise RecoveryRequired('rollback reservation checksum mismatch')
  os.replace(ready,binary); fsync_directory(binary.parent)
 if record['state_before_copy'] is None:
  if os.path.lexists(state): state.unlink(); fsync_directory(ROOT)
 elif not state.exists() or digest(state)!=record['state_before_sha256']:
  before=pathlib.Path(record['state_before_copy'])
  if not before.exists() or digest(before)!=record['state_before_sha256']: raise RecoveryRequired('rollback state snapshot is missing')
  os.replace(before,state); fsync_directory(ROOT)
 ensure_running(binary,config,unit,expected,record['config_sha256'],record['unit_sha256'])
 cleanup_transaction(record)

def recover_transaction(role,binary,config,unit,state):
 path=intent_path(role)
 if not os.path.lexists(path): return None
 try:
  record=validate_intent(read_record(path),role,binary,config,unit)
  if record['phase']=='committed':
   # Commit is durable only after the new rollback state was fsynced. An
   # interrupted cleanup must never roll a successfully committed release back.
   expected_state=dict(previous=record['previous'],sha256=record['old_sha256'])
   if digest(binary)!=record['new_sha256'] or read_record(state)!=expected_state: raise RecoveryRequired('committed deployment changed outside transaction')
   ensure_running(binary,config,unit,record['new_sha256'],record['config_sha256'],record['unit_sha256'])
   cleanup_transaction(record)
   return 'committed'
  restore_transaction(record,binary,config,unit,state)
  return 'rolled_back'
 except BaseException as error:
  raise RecoveryRequired('transaction recovery remains pending') from error

def change_release(role,binary,config,unit,state,candidate):
 record=begin_transaction(role,binary,config,unit,candidate,state)
 try:
  atomic(candidate,binary)
  run('systemctl','restart',unit)
  time.sleep(2)
  validate_running(binary,config,unit,record['new_sha256'],record['config_sha256'],record['unit_sha256'])
  write_json(state,dict(previous=record['previous'],sha256=record['old_sha256']))
  record['phase']='committed'
  write_json(intent_path(role),record)
 except BaseException:
  # A commit-record fsync can fail after rename. Re-publish prepared before
  # rolling back so an interruption during recovery cannot look committed.
  if record['phase']!='prepared':
   record['phase']='prepared'
   try:
    if read_record(intent_path(role))!=record: write_json(intent_path(role),record)
   except BaseException as error: raise RecoveryRequired('could not persist rollback intent') from error
  try: restore_transaction(record,binary,config,unit,state)
  except BaseException as error: raise RecoveryRequired('automatic rollback remains pending') from error
  raise
 cleanup_pending=False
 try: cleanup_transaction(record)
 except OSError: cleanup_pending=True
 return cleanup_pending

def ensure_release_directory():
 ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
 root_info=ROOT.lstat()
 if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid!=0 or root_info.st_mode&0o022: raise RuntimeError('release directory is not root-owned and private')

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('action',choices=['upgrade','rollback','recover','status','health','diagnose'])
 p.add_argument('--role',required=True,choices=['server','client'])
 p.add_argument('--bundle',type=pathlib.Path)
 a=p.parse_args(); unit='mygotunnel-'+a.role+'.service'
 binary=pathlib.Path('/usr/local/bin/mygotunnel-'+a.role)
 config=pathlib.Path('/etc/mygotunnel/'+a.role+'.json')
 if a.action in ('health','diagnose'):
  return subprocess.call([str(binary),'-config',config,'-health' if a.action=='health' else '-check-config'])
 if a.action=='status':
  print(json.dumps(dict(build=identity(binary),active=run('systemctl','is-active',unit),sha256=digest(binary),recovery_pending=recovery_pending(a.role))))
  return 0
 if os.geteuid()!=0: p.error('upgrade/rollback/recover requires root')
 ensure_release_directory()
 with open(ROOT/(a.role+'.lock'),'a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  state=ROOT/(a.role+'.json')
  recovered=recover_transaction(a.role,binary,config,unit,state)
  if recovered is not None or a.action=='recover':
   print(json.dumps(dict(ok=True,action='recover',requested_action=a.action,recovery_only=True,recovered=recovered,build=identity(binary),sha256=digest(binary))))
   return 0
  with tempfile.TemporaryDirectory(prefix='.'+a.role+'-stage-',dir=ROOT) as stage_path:
   stage=pathlib.Path(stage_path)
   if a.action=='upgrade':
    if not a.bundle: p.error('--bundle is required for upgrade')
    bundle=a.bundle.resolve()
    arch={'aarch64':'arm64','x86_64':'amd64'}.get(platform.machine())
    if arch is None: p.error('unsupported architecture')
    candidate=prepare_upgrade(bundle,a.role,arch,stage)
   else:
    old=read_record(state)
    require_plain_binary(pathlib.Path(old['previous']))
    candidate=stage_verified(pathlib.Path(old['previous']),stage,old['sha256'])
   cleanup_pending=change_release(a.role,binary,config,unit,state,candidate)
   print(json.dumps(dict(ok=True,action=a.action,build=identity(binary),sha256=digest(binary),transaction_cleanup_pending=cleanup_pending)))
 return 0
if __name__=='__main__':
 try: raise SystemExit(main())
 except Exception as e:
  # subprocess errors/invalid manifests must not dump config content.
  print(json.dumps(dict(ok=False,error=type(e).__name__))); raise SystemExit(1)
