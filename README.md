# agentfs-cve — AFS-NFS-01 proof pack

CVE submission pack for a confirmed NFSv3 path-escape vulnerability in
[tursodatabase/agentfs](https://github.com/tursodatabase/agentfs) `serve nfs`
overlay mode. Reproduced end-to-end on the clean `v0.6.4` release tag.

## The bug in one sentence

The NFS LOOKUP handler forwards client-controlled filenames verbatim to
`HostFS::lookup` → `openat(parent_fd, name, O_PATH|O_NOFOLLOW)` with no
single-component check and no root containment. Absolute paths ignore
`parent_fd`; `..` sequences escape the export base. Every read also triggers
a full-file copy-up into the SQLite delta, giving an availability impact.

## Affected

- `agentfs` / `agentfs-sdk` v0.6.4 tag (`3a5ed2b88e5d5a5f9b2c7fe02d012b50fd19e3c0`)
- `0a014eb` (2 commits ahead; vulnerable files identical)
- Likely all releases exposing `serve nfs`/`nfs` overlay mode; macOS
  source-level affected (runtime pending)

## Severity

- **High 7.1** — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H`
- **9.1** if `--bind` exposes the port off-loopback (`AV:N/…/A:H`)
- **5.5** conservative without availability (`…/C:H/I:N/A:N`)

## What is proven (clean v0.6.4 tag build)

- `LOOKUP /etc/passwd`, `LOOKUP ../outside_secret.txt` → host file read
- `LOOKUP ../secret_600.txt` + `AUTH_UNIX uid=0` → mode-600 server-owned file
- `LOOKUP /` + `READDIR` → host root enumeration; `/home`, `/tmp` listable
- `LOOKUP .agentfs/v064poc.db-wal` → AgentFS DB/WAL markers recovered
- 1-byte READ of 128 MB sparse file → RSS 66→551 MB, DB+WAL +464 MB in 0.9 s
- WRITE/MKDIR/REMOVE on traversed paths → delta-only; host unchanged

## Repo layout

- `README.md` — this file
- `report_20261123_181454.md` — full red-team report
- `pocs/` — raw ONC RPC Python clients (traversal, enum, db_read, exhaust)
- `evidence/` — record-marked RPC captures (`result.json` + `.record.bin`),
  wire dumps, source snippets, environment, `SHA256SUMS.txt`
- `cve-submission/` — VulnCheck/GitHub-advisory pack:
  - `advisory.md` — paste-ready advisory (120-day disclosure)
  - `attack-path-simple.md` — plain-language narrative
  - `attacker-cost.md` — effort/exposure analysis
  - `range-verification.txt` — version scope + clean-tag build notes
  - `MANIFEST.txt` — submission file list
  - `pocs/` — copies of the PoC clients

## Reproduce

```bash
git clone https://github.com/tursodatabase/agentfs.git && cd agentfs
git checkout v0.6.4
# build-only patch for vendored branches-0.4.4 (see range-verification.txt)
cd cli && cargo +stable build --release --no-default-features

mkdir -p /tmp/lab/base && echo MARKER > /tmp/lab/base/inside.txt
agentfs init --base /tmp/lab/base poc
agentfs serve nfs poc --bind 127.0.0.1 --port 11111

python3 pocs/nfs_traversal_capture.py --name /etc/passwd --read 256 --uid 0 --gid 0 --outdir out/abs
python3 pocs/nfs_enum.py out/enum 11111
python3 pocs/nfs_db_read.py out/db
python3 pocs/nfs_exhaust.py out/exhaust
```

## Separate finding

`agentfs serve mcp --tools` filters `tools/list` but `tools/call` dispatches
hidden tools anyway (CWE-862, confirmed live). Documented in report §4.2;
not part of this CVE pack.

## Status

Reported privately 2026-11-23. Awaiting vendor response / CVE assignment.
Disclosure deadline: 120 days from report (VulnCheck policy).
