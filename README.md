# agentfs-cve — AFS-NFS-01 proof pack

CVE submission pack for a confirmed NFSv3 path-escape vulnerability in
[tursodatabase/agentfs](https://github.com/tursodatabase/agentfs) `serve nfs`
overlay mode. Reproduced end-to-end on source checked out at the `v0.6.4`
release tag (build-only dependency patch; no agentfs source modified — see
`cve-submission/build-patch-v064.diff`).

All findings verified against `tursodatabase/agentfs` @ `v0.6.4`
(`3a5ed2b88e5d5a5f9b2c7fe02d012b50fd19e3c0`); `0a014eb` has identical
vulnerable files.

## Contents

- [Contents](#contents)
- [Timeline](#timeline)
- [Vulnerabilities found](#vulnerabilities-found)
- [The bug, simply](#the-bug-simply)
- [Attack path](#attack-path)
- [Potential harm](#potential-harm)
- [Affected](#affected)
- [Severity](#severity)
- [What is proven (v0.6.4 tag source)](#what-is-proven-v064-tag-source)
- [Two distinct vulnerability candidates](#two-distinct-vulnerability-candidates)
- [Repo layout](#repo-layout)
- [Reproduce](#reproduce)
- [Report metadata](#report-metadata)
- [Disclosure status](#disclosure-status)
- [Evidence](#evidence)
- [License](#license)

## Timeline

| UTC | Event | Proof |
|---|---|---|
| 2026-11-23T18:05:28Z–19:16:49Z | PoC verification on `agentfs` built from upstream `v0.6.4` tag source: traversal, absolute path, mode-600 uid spoof, enumeration, DB/WAL read, copy-up exhaustion | [report](cve-submission/report_20261123_181454.md) · [evidence/captures](evidence/captures/) |
| 2026-11-23T20:05:57Z–20:06:18Z | Listener-correlated kernel OOM kill of the `agentfs serve nfs` PID after 1-byte READ of a 1 TB sparse file | [v064-crash-oom](evidence/captures/v064-crash-oom/) |
| 2026-11-23T20:40:10Z | Vendor report emailed to `security@turso.tech` (cc `info@turso.tech`) with `agentfs-cve-submission-20261123.zip` | [vendor .eml](disclosure/sent/20261123T204010Z-vendor-security-report-agentfs-nfs01.eml) · [contact log](disclosure/contact-log.md) |
| 2026-11-23T20:41Z | Turso support auto-ack received as ticket `TUR-277` | [contact log](disclosure/contact-log.md) · [report disclosure timeline](cve-submission/report_20261123_181454.md#disclosure-timeline-utc) — raw `.eml` not archived yet |
| 2026-11-23T20:44Z | Clarification reply sent on `TUR-277` requesting security-team routing | [contact log](disclosure/contact-log.md) · [report disclosure timeline](cve-submission/report_20261123_181454.md#disclosure-timeline-utc) — raw `.eml` not archived yet |
| 2026-11-24T20:38:47Z | Report repository `Teycir/agentfs-cve` created public as the reproduction package | <https://github.com/Teycir/agentfs-cve> |
| pending | VulnCheck submission for AFS-NFS-01 | [submission/vulncheck/timeline.md](submission/vulncheck/timeline.md) |

## Vulnerabilities found

| ID | Vulnerability | Severity | CVSS 3.1 | Status |
|---|---|---|---|---|
| AFS-NFS-01 | NFSv3 overlay LOOKUP path escape → arbitrary host file disclosure + server DoS | High | 7.7 `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H` | Vendor contacted 2026-11-23; VulnCheck pending |
| AFS-MCP-01 | MCP `--tools` allowlist filters discovery but not `tools/call` invocation | Low | 3.1 `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` | Confirmed; separate candidate, not in this submission |
| — | OBS-01: `HostFS` mutating ops exist but are unreachable via overlay NFS | Informational | — | Hardening note |
| — | OBS-02: `tcpdump` unavailable in lab (`CAP_NET_RAW`); record-level captures used | Informational | — | Environment note |

Details, evidence, and PoCs: [`cve-submission/report_20261123_181454.md`](cve-submission/report_20261123_181454.md) · Submission drafts: [`cve-submission/`](cve-submission/) · Disclosure contact log: [`disclosure/contact-log.md`](disclosure/contact-log.md)

## The bug, simply

`agentfs serve nfs` shares a folder over NFS. The server takes filenames from the
network and asks the host filesystem to open them without checking that the name
is a single safe path inside the shared folder. A client can ask for
`/etc/passwd` or `../secret` and the server reads host files outside the export;
large files also crash it by copying them into memory first.

## Attack path

```text
raw ONC RPC client
  -> MOUNT export
  -> LOOKUP "/etc/passwd" or "../secret_600.txt"
  -> AgentNFS::lookup passes the client name unchanged
  -> OverlayFS::lookup -> HostFS::lookup
  -> openat(parent_fd, name) / parent.join(name)
  -> host file outside the export base returned over NFS

availability branch:
  READ base-backed inode -> copy_up whole file -> RSS + SQLite DB/WAL growth -> OOM kill
```

## Potential harm

- **Confidentiality:** arbitrary read/stat and directory enumeration of host files accessible to the `agentfs` process, including mode-600 files via self-asserted `AUTH_UNIX uid=0`.
- **AgentFS database disclosure:** when `.agentfs/<id>.db*` paths are known or discoverable, the same primitive reads the SQLite DB/WAL files.
- **Availability:** copy-up amplification can crash the NFS listener; verified with a 1-byte READ of a 1 TB sparse file → ~51.5 GB RSS → kernel OOM kill.
- **Integrity:** no host write/delete demonstrated; overlay-view whiteouts can hide base files from other clients of the same export.
- **Exposed deployments:** developers/CI running `agentfs serve nfs` on shared hosts or containers; off-loopback binds expose the port remotely. macOS is source-level affected; runtime validation pending.

## Affected

- `agentfs` / `agentfs-sdk` v0.6.4 tag (`3a5ed2b88e5d5a5f9b2c7fe02d012b50fd19e3c0`)
- `0a014eb` (2 commits ahead; vulnerable files identical)
- Other versions exposing `serve nfs`/`nfs` overlay mode may be affected; not systematically verified
- macOS source-level affected (runtime pending)

## Severity

- **High 7.7** — `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H`
- **9.1** if `--bind` exposes the port off-loopback (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H`)
- **6.2** conservative without availability (`AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)

## What is proven (v0.6.4 tag source)

- `LOOKUP /etc/passwd`, `LOOKUP ../outside_secret.txt` → host file read
- `LOOKUP ../secret_600.txt` + `AUTH_UNIX uid=0` → mode-600 server-owned file
- `LOOKUP /` + `READDIR` → host root enumeration; `/home`, `/tmp` listable
- `LOOKUP .agentfs/v064poc.db-wal` → AgentFS DB/WAL markers recovered
- 1-byte READ of 128 MB sparse file → RSS 66→551 MB, DB+WAL +464 MB in 0.9 s
- 1-byte READ of 1 TB sparse file → ~51.5 GB RSS → kernel OOM-killed the `ss`-identified `agentfs` listener PID
- WRITE/MKDIR/REMOVE on traversed paths → delta-only; host unchanged

## Two distinct vulnerability candidates

This engagement produced **two separate vulnerability candidates**, submitted
independently — not bundled:

| ID | Vulnerability | Severity | CVE potential |
|---|---|---|---|
| AFS-NFS-01 | NFS filesystem path traversal → arbitrary host file disclosure + server DoS | High (7.7) | Strong — this pack |
| AFS-MCP-01 | MCP `--tools` allowlist bypass → unauthorized tool invocation | Low (3.1) | Possible, subject to CNA criteria |

**AFS-NFS-01** is the primary submission: everything in this pack
(`advisory.md`, PoCs, `evidence/`).

**AFS-MCP-01** is documented in report §4.2 with evidence
(`evidence/mcp_filter_bypass.*`); it has a different root cause, security
boundary, and impact, and is excluded from the NFS advisory.

## Repo layout

- `README.md` — this file
- `disclosure/contact-log.md` — authoritative contact log (Message-IDs, statuses, watch items)
- `disclosure/sent/` — archived outbound `.eml` + `SHA256SUMS`
- `submission/vulncheck/timeline.md` — VulnCheck-facing UTC timeline with direct artifact links
- `cve-submission/report_20261123_181454.md` — full red-team report (authoritative copy)
- `pocs/` — raw ONC RPC Python clients (traversal, enum, db_read, exhaust, crash)
- `evidence/` — record-marked RPC captures (`result.json` + `.record.bin`), wire dumps, source snippets, environment, `SHA256SUMS.txt`
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

## Report metadata

| Field | Value |
|---|---|
| Target | `agentfs` / `agentfs-sdk` 0.6.4, `tursodatabase/agentfs` |
| Release tag | `v0.6.4` = `3a5ed2b88e5d5a5f9b2c7fe02d012b50fd19e3c0` |
| Also tested | `0a014ebd4918615baff589ed17486e557e7c6a23` (2 commits ahead of tag; only `cli/src/cmd/init.rs`, `cli/src/cmd/ps.rs` differ — vulnerable files identical) |
| Engagement dir | `/home/teycir/BugBounty/agentfs/20261123/180528` |
| Generated (UTC) | 2026-11-23T18:14:54Z; updated 2026-11-23T20:41Z |
| Tested binaries | build from source checked out at the `v0.6.4` tag: `agentfs v0.6.4-dirty`, sha256 `8abbf5f926f358739f0b600e185f6efd425eaaa89c07b0b2b573b44d2b16c0c4` (stable rustc 1.95.0, `--release --no-default-features`, build-only `branches-0.4.4` patch — see `range-verification.txt`); earlier `0a014eb-dirty` sha256 `048742a1…` |
| Scope | Local source audit + live loopback NFSv3/MCP PoCs; non-destructive reads; lab-only writes |
| Status | FINAL — AFS-NFS-01 confirmed on v0.6.4 tag source; AFS-MCP-01 confirmed |
| Disclosure | AFS-NFS-01 submitted privately via email to `security@turso.tech` on 2026-11-23T20:40Z (package: `agentfs-cve-submission-20261123.zip`). Auto-ack received as support ticket **TUR-277**; clarification reply sent 2026-11-23T20:44Z requesting security-team routing. Repo public since 2026-11-24T20:38:47Z. VulnCheck submission pending. No fixed deadline committed; publication coordinated with the vendor/CNA. AFS-MCP-01 not included in this submission. |

## Disclosure status

AFS-NFS-01 was submitted privately via email to `security@turso.tech` on
2026-11-23T20:40Z (attachment: `agentfs-cve-submission-20261123.zip`).
Auto-ack received as support ticket **TUR-277**; clarification reply sent
2026-11-23T20:44Z requesting security-team routing. Awaiting security
designated response / CVE assignment. The repo has no `SECURITY.md` and
GitHub private vulnerability reporting is disabled — email is the
published channel per `turso.tech/.well-known/security.txt`.
AFS-MCP-01 was not included in this submission.
Disclosure: coordinated with the vendor, no fixed deadline.

Contact evidence: [`disclosure/sent/20261123T204010Z-vendor-security-report-agentfs-nfs01.eml`](disclosure/sent/20261123T204010Z-vendor-security-report-agentfs-nfs01.eml) · [`disclosure/contact-log.md`](disclosure/contact-log.md) · [`submission/vulncheck/timeline.md`](submission/vulncheck/timeline.md)

## Evidence

- `evidence/captures/*/result.json` + `*.record.bin` — UTC timestamps, RPC statuses, auth, sha256 per record
- `evidence/captures/v064-crash-oom/` — OOM-kill evidence incl. `kernel-oom.log`
- `evidence/wire_hex_*.txt` — xxd dumps of key exchanges
- `evidence/source_snippets.txt` — vulnerable code excerpts with line numbers
- `evidence/environment.txt` / `environment-v064.txt` — build environments + binary hash
- `evidence/SHA256SUMS.txt` — integrity manifest for `evidence/`
- `disclosure/sent/SHA256SUMS` — integrity manifest for archived `.eml`

## License

[MIT License](LICENSE) — Copyright (c) 2026 Teycir
