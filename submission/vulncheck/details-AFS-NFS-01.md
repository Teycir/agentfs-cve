# AFS-NFS-01 — agentfs `serve nfs` overlay path escape → arbitrary host file disclosure + server DoS

**Severity:** High — CVSS 3.1 **7.7** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H` ([calculator](https://www.first.org/cvss/calculator/3.1#CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H))
**Alternate scores:** 9.1 if bound off-loopback (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H`); 6.2 conservative without availability (`AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
**CWE:** CWE-22 (Pathname to Restricted Directory), CWE-73 (External Control of File Name or Path)

## Affected software

- Vendor: Turso (`tursodatabase` GitHub org)
- Product: AgentFS / `agentfs` / `agentfs-sdk`
- Confirmed affected: `v0.6.4` tag `3a5ed2b88e5d5a5f9b2c7fe02d012b50fd19e3c0`
- Also affected: `0a014ebd4918615baff589ed17486e557e7c6a23` (2 commits ahead; vulnerable files identical)
- Other versions exposing `serve nfs` / `agentfs nfs` overlay mode may be affected; not systematically verified
- macOS backend is source-level affected; runtime validation pending

## Summary

`agentfs serve nfs` exports an overlay filesystem whose read-only base is a host directory (`HostFS`). The NFSv3 LOOKUP handler forwards client-controlled `filename3` values to the filesystem backend without enforcing single-component path semantics or ensuring resolution remains beneath the configured `HostFS` root.

An unauthenticated raw ONC RPC client can MOUNT the export and LOOKUP/READ host files outside the configured base — `/etc/passwd`, mode-600 files owned by the server user (with self-asserted `AUTH_UNIX uid=0`) — and enumerate host directories via READDIR. When `.agentfs/<id>.db*` paths are known or discoverable, the same primitive reads the AgentFS SQLite DB/WAL files.

Every open on a base-backed inode also triggers a full-file copy-up into the SQLite delta. A 1-byte READ of a 128 MB sparse file raised server RSS 66 MB → 551 MB peak and grew DB+WAL by ~464 MB in 0.9 s. A 1-byte READ of a 1 TB sparse file drove RSS to ~51.5 GB and the kernel OOM-killed the `ss`-identified `agentfs` listener PID — verified via `journalctl -k` and post-crash probes.

Host file write/delete is NOT possible through this path — all mutations are redirected to the SQLite delta (verified live).

## Root cause

- `cli/src/cmd/nfs.rs` — overlay mode wraps `HostFS::new(base_path)` in `OverlayFS` and serves it via `AgentNFS`.
- `cli/src/nfsserve/nfs_handlers.rs:256` — `nfsproc3_lookup` deserializes `diropargs3` and calls `context.vfs.lookup(dirid, &dirops.name)` after only a parent execute check.
- `cli/src/nfs.rs:122` — `AgentNFS::lookup` forwards the network filename unchanged.
- `sdk/rust/src/filesystem/overlayfs.rs:632` — `OverlayFS::lookup` delegates `self.base.lookup(base_parent_ino, name)` with the raw name; `:957` `open` copy-ups base files even for `O_RDONLY`.
- `sdk/rust/src/filesystem/hostfs_linux.rs:342` — `HostFS::lookup` uses `openat(parent_fd, name, O_PATH|O_NOFOLLOW)`; `hostfs_darwin.rs:334` uses `parent_path.join(name)` (absolute replaces parent).
- `cli/src/nfsserve/permissions.rs` — `check_permission` returns true for `auth.uid == 0`; credentials are client-supplied.

Negative control: `LOOKUP ".."` at the export root is clamped by the AgentFS delta layer. The exploit uses absolute paths and slash/`..`-containing names, which bypass that handling.

## Verified impact

- Arbitrary host file disclosure for files readable by the `agentfs` process.
- Disclosure of server-user-owned mode-600 files via AUTH_UNIX uid spoof.
- Host directory enumeration (`LOOKUP "/"` + `READDIR`; `/home`, `/tmp` listable).
- AgentFS SQLite DB/WAL disclosure when path is known/discoverable; tested WAL contained recoverable copy-up markers including `/etc/passwd` content.
- Memory/disk exhaustion via full-file copy-up on any open.
- Service crash via copy-up OOM kill (requires a sufficiently large readable file outside the export).
- Overlay-view modification: whiteouts can hide base files from other clients of the same export.
- Remote exploitation is conditional on `--bind` exposure; macOS is source-supported, runtime pending.

## Steps to reproduce

Full runnable PoCs, record-marked RPC captures, wire dumps, source snippets, environment details, and SHA-256 manifests are in the public report repository: **https://github.com/Teycir/agentfs-cve**

Minimal path:

1. Build `agentfs` from upstream `v0.6.4` tag source using the documented build-only dependency patch (`cve-submission/build-patch-v064.diff`; vendors `branches-0.4.4`, no agentfs source modified).
2. `agentfs init --base /tmp/lab/base poc`
3. `agentfs serve nfs poc --bind 127.0.0.1 --port 11111`
4. From the repo root run the included raw ONC RPC clients:

```bash
python3 pocs/nfs_traversal_capture.py --name /etc/passwd --read 256 --uid 0 --gid 0 --port 11111 --outdir out/abs
python3 pocs/nfs_enum.py --outdir out/enum --port 11111 --paths / /home /tmp
python3 pocs/nfs_db_read.py --outdir out/db --port 11111 --db /path/to/.agentfs/<export>.db-wal
truncate -s 1T /tmp/lab/huge_sparse.bin    # WARNING: crashes the server
python3 pocs/nfs_crash.py --outdir out/crash --port 11111 --name ../huge_sparse.bin --server-pattern 'agentfs serve nfs'
```

Observed on `v0.6.4` tag source: MOUNT `/` succeeds; `LOOKUP "/etc/passwd"` returns `NFS3_OK`; READ returns host file bytes. READDIR of `/` returns the host root listing. The DB/WAL read recovered markers for in-base, out-of-base, mode-600, and `/etc/passwd` copy-up content. The 1 TB sparse READ dropped the connection after ~18 s; the `ss`-identified listener PID was OOM-killed, the listener disappeared, the port refused connections, and the post-crash MOUNT probe failed with ConnectionRefusedError.

## Recommended fix

1. Enforce single-component LOOKUP names in `AgentNFS`/`nfsproc3_*`: reject `/` (path separator), NUL, empty names, and names > `NAME_MAX`. Do not reject all `..` — NFS clients legitimately navigate parents.
2. Root-aware parent navigation: `..` at the export root must return the export root, never the host parent.
3. Defense in depth in `HostFS`: per-component `openat` resolution rejecting `..`/absolute paths, or `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS` on Linux / descriptor-relative confinement on macOS.
4. Do not copy up on read-only opens; serve `O_RDONLY` from the base fd and stream `pread` without materializing the whole file.
5. Treat AUTH_UNIX uid/gid as untrusted (root-squash or real auth); document OS process credentials as the real boundary.

## Disclosure

Vendor contacted first via `security@turso.tech` on 2026-11-23T20:40:10Z with the full evidence package; Turso support auto-ack ticket `TUR-277`; clarification reply sent 2026-11-23T20:44Z requesting security-team routing. Report repository is public as the reproduction package. Timing is flexible and deferred to the vendor/CNA; no fixed-day embargo is proposed.

Separate finding not included here: `agentfs serve mcp --tools` filters `tools/list` but `tools/call` dispatches hidden tools anyway (CWE-862), documented in the report §4.2.
