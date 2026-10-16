#!/usr/bin/env python3
"""Bounded 72h passive journal/process observation; no config/credentials stored.
Setup percentiles are successful setup latency, not per-packet RTT.
Failure rate counts unique connection IDs with failed before ready. Relay errors
are counted separately. Histograms are 1ms through 60s plus overflow, rounded up.
"""
import argparse,collections,datetime,json,math,os,pathlib,re,subprocess,time

def command(*args):
 return subprocess.check_output(args,text=True,stderr=subprocess.DEVNULL,timeout=20)
def percentile(hist,q):
 n=sum(hist.values())
 if not n: return None
 cutoff=math.ceil(n*q); count=0
 for value,amount in sorted(hist.items()):
  count+=amount
  if count>=cutoff: return value

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--role',choices=['client','server'],required=True)
 p.add_argument('--output',type=pathlib.Path,required=True)
 p.add_argument('--hours',type=float,default=72)
 p.add_argument('--interval',type=float,default=30)
 a=p.parse_args()
 if not 0<a.hours<=72 or a.interval<1: p.error('hours must be (0,72], interval >=1s')
 a.output.mkdir(parents=True,exist_ok=True,mode=0o700)
 os.umask(0o077)
 unit='mygotunnel-'+a.role+'.service'; start=time.time(); end=start+a.hours*3600
 hist=collections.Counter(); ready=failed=relay=0; cursor=None; seen=collections.OrderedDict(); baseline=None; maxima={}
 def utc(t): return datetime.datetime.fromtimestamp(t,datetime.timezone.utc).isoformat()
 (a.output/'schedule.json').write_text(json.dumps(dict(start=utc(start),end=utc(end),role=a.role)))
 with (a.output/'samples.jsonl').open('x') as out:
  while True:
   now=time.time(); row=dict(time=utc(now),role=a.role)
   try:
    properties=command('systemctl','show',unit,'-p','MainPID','-p','NRestarts','-p','ActiveState','-p','InvocationID')
    props=dict(x.split('=',1) for x in properties.splitlines() if '=' in x)
    row.update(props); pid=int(props['MainPID'])
    if pid:
     status=(pathlib.Path('/proc')/str(pid)/'status').read_text()
     row['rss_bytes']=int(re.search(r'VmRSS:\s+(\d+)',status).group(1))*1024
     row['fd_count']=len(list((pathlib.Path('/proc')/str(pid)/'fd').iterdir()))
     row['tcp_connections']=sum(('pid='+str(pid)+',') in line for line in command('ss','-Htnp').splitlines())
    args=['journalctl','-u',unit,'-o','json','--no-pager','--output-fields=__CURSOR,MESSAGE']
    args += ['--after-cursor',cursor] if cursor else ['--since','@'+str(start)]
    # Read every 30s. A bounded journal batch prevents memory spikes.
    args += ['-n','20000']
    raw=command(*args).splitlines()
    row['journal_batch_limit_reached']=len(raw)>=20000
    for line in raw:
     event=json.loads(line); cursor=event.get('__CURSOR',cursor); msg=event.get('MESSAGE','')
     try:
      fields=json.loads(msg); kind=fields.get('msg'); ident=fields.get('connection_id'); duration=fields.get('setup_duration',0)/1e6
     except (ValueError,TypeError):
      m=re.search(r'^\S+ \S+ \S+ [CS] (ready|failed|stats)\b',msg); kind=m.group(1) if m else None
      m=re.search(r'\bid=([^ ]+)',msg); ident=m.group(1) if m else None
      m=re.search(r'\btotal=([0-9.]+)ms',msg); duration=float(m.group(1)) if m else None
      fields={k:int(v) for k,v in re.findall(r'\b(active|setup|idle|rejected|udp_sockets|udp_buffer_bytes)=(\d+)',msg)}
     if kind=='stats': row['resources']=fields if not msg.startswith('{') else {k:v for k,v in fields.items() if isinstance(v,(int,float))}
     if not ident or kind not in ('ready','failed'): continue
     previous=seen.get(ident)
     if kind=='ready' and previous is None:
      ready+=1; seen[ident]='ready'
      if duration is not None: hist[min(60001,math.ceil(duration))]+=1
     elif kind=='failed':
      if previous=='ready': relay+=1
      elif previous is None: failed+=1
      seen[ident]='failed'
     while len(seen)>100000: seen.popitem(last=False)
    row.update(ready=ready,setup_failed=failed,relay_failed=relay,failure_rate=failed/(ready+failed) if ready+failed else None,p95_setup_ms=percentile(hist,.95),p99_setup_ms=percentile(hist,.99))
   except Exception as e: row['collection_error']=type(e).__name__
   out.write(json.dumps(row)+'\n'); out.flush()
   if baseline is None and 'rss_bytes' in row: baseline={k:row[k] for k in ('rss_bytes','fd_count','tcp_connections')}
   for k in ('rss_bytes','fd_count','tcp_connections'):
    if k in row: maxima[k]=max(maxima.get(k,0),row[k])
   summary=dict(row,baseline=baseline,maxima=maxima,start=utc(start),scheduled_end=utc(end),complete=time.time()>=end,latency_semantics='successful setup; 1ms rounded-up histogram; 60001 means >60s',failure_semantics='unique connection failed before ready; relay failures separate; includes real user/auth failures')
   tmp=a.output/'summary.tmp'; tmp.write_text(json.dumps(summary,indent=2)); os.replace(tmp,a.output/'summary.json')
   if time.time()>=end: break
   time.sleep(min(a.interval,end-time.time()))
if __name__=='__main__': main()
