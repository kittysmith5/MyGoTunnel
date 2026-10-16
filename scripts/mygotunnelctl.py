#!/usr/bin/env python3
"""Local root-only atomic upgrades. Bundles must come from a trusted source.
Hashes detect transfer corruption; they do not authenticate the publisher.
"""
import argparse,fcntl,hashlib,json,os,pathlib,platform,shutil,socket,subprocess,tempfile,time

ROOT=pathlib.Path('/var/lib/mygotunnel/releases')
def run(*args):
 return subprocess.check_output(args,text=True,stderr=subprocess.DEVNULL,timeout=45).strip()
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def atomic(src,dst):
 fd,tmp=tempfile.mkstemp(prefix='.mygotunnel-',dir=dst.parent)
 try:
  with os.fdopen(fd,'wb') as f:
   with open(src,'rb') as r: shutil.copyfileobj(r,f)
   f.flush(); os.fsync(f.fileno())
  os.chmod(tmp,0o755); os.replace(tmp,dst)
 finally:
  if os.path.exists(tmp): os.unlink(tmp)
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
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('action',choices=['upgrade','rollback','status','health','diagnose'])
 p.add_argument('--role',required=True,choices=['server','client'])
 p.add_argument('--bundle',type=pathlib.Path)
 a=p.parse_args(); unit='mygotunnel-'+a.role+'.service'
 binary=pathlib.Path('/usr/local/bin/mygotunnel-'+a.role)
 config='/etc/mygotunnel/'+a.role+'.json'
 if a.action in ('health','diagnose'):
  return subprocess.call([str(binary),'-config',config,'-health' if a.action=='health' else '-check-config'])
 if a.action=='status':
  print(json.dumps(dict(build=identity(binary),active=run('systemctl','is-active',unit),sha256=digest(binary))))
  return 0
 if os.geteuid()!=0: p.error('upgrade/rollback requires root')
 ROOT.mkdir(parents=True,exist_ok=True,mode=0o700)
 with open(ROOT/(a.role+'.lock'),'w') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  state=ROOT/(a.role+'.json')
  if a.action=='upgrade':
   if not a.bundle: p.error('--bundle is required for upgrade')
   bundle=a.bundle.resolve(); manifest=json.loads((bundle/'manifest.json').read_text())
   arch={'aarch64':'arm64','x86_64':'amd64'}.get(platform.machine())
   if arch is None: p.error('unsupported architecture')
   name=a.role+'-linux-'+arch; candidate=bundle/name
   if digest(candidate)!=manifest['files'][name]: raise RuntimeError('bundle checksum mismatch')
   candidate_info=json.loads(run(str(candidate),'-version'))
   if candidate_info['commit']!=manifest['commit'] or candidate_info['version']!=manifest['version']: raise RuntimeError('build identity mismatch')
  else:
   old=json.loads(state.read_text()); candidate=pathlib.Path(old['previous'])
   if digest(candidate)!=old['sha256']: raise RuntimeError('rollback checksum mismatch')
  # Validate before replacement, without printing config or credentials.
  check(candidate,config)
  before=digest(pathlib.Path(config)); unit_before=run('systemctl','cat',unit)
  saved=ROOT/(a.role+'-'+time.strftime('%Y%m%dT%H%M%SZ')+'-'+str(time.time_ns()))
  shutil.copy2(binary,saved); old_hash=digest(saved)
  atomic(candidate,binary)
  try:
   run('systemctl','restart',unit)
   time.sleep(2)
   run('systemctl','is-active',unit)
   check(binary,config,health=True)
   if before!=digest(pathlib.Path(config)) or unit_before!=run('systemctl','cat',unit): raise RuntimeError('configuration changed')
   pid=run('systemctl','show','-p','MainPID','--value',unit)
   if digest(pathlib.Path('/proc')/pid/'exe')!=digest(binary): raise RuntimeError('running executable mismatch')
  except BaseException:
   atomic(saved,binary); run('systemctl','restart',unit)
   raise
  temporary=state.with_suffix('.tmp')
  temporary.write_text(json.dumps(dict(previous=str(saved),sha256=old_hash)))
  os.chmod(temporary,0o600); os.replace(temporary,state)
  print(json.dumps(dict(ok=True,action=a.action,build=identity(binary),sha256=digest(binary))))
 return 0
if __name__=='__main__':
 try: raise SystemExit(main())
 except Exception as e:
  # subprocess errors/invalid manifests must not dump config content.
  print(json.dumps(dict(ok=False,error=type(e).__name__))); raise SystemExit(1)
