#!/usr/bin/env python3
"""Bounded passive journal/process observation, scoped to an explicit service.
Setup percentiles describe successful setup, not packet RTT. Complete requires
both elapsed observation time and full collection coverage. No payloads stored.
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


def parse_message(message):
 try:
  fields=json.loads(message)
  if isinstance(fields,dict): return fields
 except (ValueError,TypeError): pass
 match=re.search(r'^\S+ \S+ \S+ [CS] (ready|failed|closed|stats)\b',message)
 if not match: return {}
 fields={'msg':match.group(1)}
 aliases={'id':'connection_id','phase':'failure_phase','reason':'close_reason'}
 for key,value in re.findall(r'\b([a-zA-Z_]\w*)=([^\s]+)',message):
  if key in ('id','stage','phase','reason'):
   fields[aliases.get(key,key)]=value
  elif re.fullmatch(r'\d+(?:\.\d+)?(?:/\d+)?',value):
   number,_,limit=value.partition('/')
   fields[key]=float(number) if '.' in number else int(number)
   if limit: fields[key+'_limit']=int(limit)
 match=re.search(r'\btotal=([0-9.]+)ms',message)
 if match: fields['setup_duration']=float(match.group(1))*1e6
 return fields


class Aggregator:
 def __init__(self,limit=100000):
  self.limit=limit; self.active=collections.OrderedDict(); self.finished=collections.OrderedDict()
  self.hist=collections.Counter(); self.ready=0; self.setup_failed=0; self.relay_failed=0; self.shutdown_failed=0; self.auth_failed=0
  self.tracking_gaps=0; self.resources=None
  self.setup_stages=collections.Counter(); self.setup_reasons=collections.Counter(); self.relay_reasons=collections.Counter(); self.shutdown_reasons=collections.Counter()
 def consume(self,message):
  f=parse_message(message); kind=f.get('msg'); ident=f.get('connection_id')
  if kind=='stats':
   self.resources={k:v for k,v in f.items() if isinstance(v,(int,float)) and not isinstance(v,bool)}
  if not ident or kind not in ('ready','failed','closed'): return
  if kind=='ready':
   if ident in self.active or ident in self.finished: return
   self.ready+=1; self.active[ident]=True
   duration=f.get('setup_duration')
   if isinstance(duration,(int,float)) and math.isfinite(duration) and duration>=0:
    self.hist[min(60001,math.ceil(duration/1e6))]+=1
   if len(self.active)>self.limit:
    self.active.popitem(last=False); self.tracking_gaps+=1
   return
  if ident in self.finished: return
  was_ready=ident in self.active; self.active.pop(ident,None)
  self.finished[ident]=True
  while len(self.finished)>self.limit: self.finished.popitem(last=False)
  if kind=='closed': return
  stage=f.get('stage','unknown'); reason=f.get('close_reason','unknown')
  if f.get('failure_phase')=='half_close':
   self.shutdown_failed+=1; self.shutdown_reasons[reason]+=1
  elif was_ready or stage in ('up','down','relay','udp_control','udp_read','udp_tunnel_read','udp_tunnel_write','udp_session'):
   self.relay_failed+=1; self.relay_reasons[reason]+=1
  else:
   self.setup_failed+=1; self.setup_stages[stage]+=1; self.setup_reasons[reason]+=1
   if stage=='auth': self.auth_failed+=1
 def snapshot(self):
  attempts=self.ready+self.setup_failed; proxy_attempts=attempts-self.auth_failed
  return dict(ready=self.ready,setup_failed=self.setup_failed,auth_failed=self.auth_failed,relay_failed=self.relay_failed,shutdown_failed=self.shutdown_failed,
   failure_rate=self.setup_failed/attempts if attempts else None,
   proxy_failure_rate=(self.setup_failed-self.auth_failed)/proxy_attempts if proxy_attempts else None,
   setup_failures_by_stage=dict(self.setup_stages),setup_failures_by_reason=dict(self.setup_reasons),relay_failures_by_reason=dict(self.relay_reasons),shutdown_failures_by_reason=dict(self.shutdown_reasons),
   latency_samples=sum(self.hist.values()),p95_setup_ms=percentile(self.hist,.95),p99_setup_ms=percentile(self.hist,.99),tracking_gaps=self.tracking_gaps)


def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--role',choices=['client','server'],required=True)
 p.add_argument('--unit',help='systemd unit; defaults to mygotunnel-<role>.service')
 p.add_argument('--output',type=pathlib.Path,required=True)
 p.add_argument('--hours',type=float,default=72)
 p.add_argument('--interval',type=float,default=30)
 p.add_argument('--journal-batch-size',type=int,default=20000)
 a=p.parse_args()
 if not math.isfinite(a.hours) or not math.isfinite(a.interval) or not 0<a.hours<=72 or a.interval<1: p.error('hours must be (0,72], interval >=1s')
 if not 1<=a.journal_batch_size<=20000: p.error('journal batch size must be 1..20000')
 unit=a.unit or 'mygotunnel-'+a.role+'.service'
 if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@:-]*\.service',unit): p.error('invalid systemd service name')
 a.output.mkdir(parents=True,exist_ok=True,mode=0o700)
 os.umask(0o077)
 start=time.time(); end=start+a.hours*3600; collector=Aggregator()
 cursor=None; baseline=None; maxima={}; batches_limited=0; collection_errors=0
 def utc(t): return datetime.datetime.fromtimestamp(t,datetime.timezone.utc).isoformat()
 (a.output/'schedule.json').write_text(json.dumps(dict(start=utc(start),end=utc(end),role=a.role,unit=unit)))
 with (a.output/'samples.jsonl').open('x') as out:
  while True:
   now=time.time(); row=dict(time=utc(now),role=a.role,unit=unit,journal_batch_limit_reached=False)
   try:
    properties=command('systemctl','show',unit,'-p','MainPID','-p','NRestarts','-p','ActiveState','-p','InvocationID')
    props=dict(x.split('=',1) for x in properties.splitlines() if '=' in x)
    row.update(props); pid=int(props['MainPID'])
    if pid:
     status=(pathlib.Path('/proc')/str(pid)/'status').read_text()
     row['rss_bytes']=int(re.search(r'VmRSS:\s+(\d+)',status).group(1))*1024
     row['fd_count']=len(list((pathlib.Path('/proc')/str(pid)/'fd').iterdir()))
     row['tcp_connections']=sum(('pid='+str(pid)+',') in line for line in command('ss','-Htnp').splitlines())
    args=['journalctl','-u',unit,'-o','json','--no-pager','--output-fields=__CURSOR,MESSAGE','--until','@'+str(min(now,end))]
    args+=['--after-cursor',cursor] if cursor else ['--since','@'+str(start)]
    # A capped tail may omit records. Preserve that coverage loss in every
    # later summary rather than resetting the flag on the next quiet batch.
    raw=command(*args,'-n',str(a.journal_batch_size)).splitlines()
    if len(raw)>=a.journal_batch_size:
     row['journal_batch_limit_reached']=True; batches_limited+=1
    for line in raw:
     event=json.loads(line); collector.consume(event.get('MESSAGE','')); cursor=event.get('__CURSOR',cursor)
   except Exception as e:
    row['collection_error']=type(e).__name__; collection_errors+=1
   row.update(collector.snapshot())
   if collector.resources is not None: row['resources']=collector.resources
   data_complete=not (batches_limited or collection_errors or collector.tracking_gaps)
   row.update(journal_batches_limited=batches_limited,collection_errors=collection_errors,data_complete=data_complete)
   out.write(json.dumps(row)+'\n'); out.flush()
   if baseline is None and 'rss_bytes' in row: baseline={k:row[k] for k in ('rss_bytes','fd_count','tcp_connections')}
   for k in ('rss_bytes','fd_count','tcp_connections'):
    if k in row: maxima[k]=max(maxima.get(k,0),row[k])
   # A command may run across the end time. Collect one final batch through
   # the scheduled end before declaring the observation finished.
   finished=now>=end
   summary=dict(row,baseline=baseline,maxima=maxima,start=utc(start),scheduled_end=utc(end),finished=finished,complete=finished and data_complete,
    latency_semantics='successful setup; 1ms rounded-up histogram; 60001 means >60s',
    failure_semantics='setup/relay/half-close separate; auth failures included in failure_rate and excluded from proxy_failure_rate')
   tmp=a.output/'summary.tmp'; tmp.write_text(json.dumps(summary,indent=2)); os.replace(tmp,a.output/'summary.json')
   if finished: break
   time.sleep(min(a.interval,max(0,end-time.time())))
if __name__=='__main__': main()
