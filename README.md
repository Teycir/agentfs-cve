# agentfs — NFS LOOKUP path escape exposes host files outside the export base

`agentfs serve nfs` exports an overlay filesystem backed by a host directory (`HostFS`).
The NFSv3 LOOKUP handler forwards the client-supplied filename verbatim to `openat()` without
rejecting `/`, `..`, or absolute paths. A raw ONC RPC client can read host files outside the
configured base — including `/etc/passwd` and mode-600 files owned by the server user when it
claims `AUTH_UNIX uid=0`.

| | |
|---|---|
| Package | `agentfs` / `agentfs-sdk` |
| Source | `github.com/tursodatabase/agentfs` |
| Confirmed | `0.6.4`, commit `0a014ebd4918615baff589ed17486e557e7c6a23` |
| Affected | Confirmed `0.6.4`; likely any release exposing `serve nfs`/`nfs` in overlay mode |
| Fixed in | none |
| Severity | Medium — CVSS 3.1 **5.5** `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| Alternate | High-ish **7.5** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` if bound off-loopback |
| CWE | CWE-22, CWE-73 |
| CVE | pending |
| Reported by | Teycir ([github.com/Teycir](https://github.com/Teycir)) |
| Status | Confirmed end-to-end; evidence archived |

## Issue

`cli/src/cmd/nfs.rs` wraps `HostFS::new(base_path)` in `OverlayFS` and serves it via
`AgentNFS`. `nfsproc3_lookup` (`cli/src/nfsserve/nfs_handlers.rs:256`) passes
`dirops.name` to `AgentNFS::lookup` (`cli/src/nfs.rs:122`), which forwards it unchanged to
`OverlayFS::lookup` (`sdk/rust/src/filesystem/overlayfs.rs:632`) and then
`HostFS::lookup` (`sdk/rust/src/filesystem/hostfs_linux.rs:342`). `HostFS::lookup` calls
`openat(parent_fd, name, O_PATH|O_NOFOLLOW)`; `O_NOFOLLOW` only protects the final component,
and an absolute pathname ignores `parent_fd` entirely.

## Reproduce

1. Build and initialize an overlay AgentFS:

```bash
cd cli
cargo build --release --no-default-features
agentfs init --base /tmp/project labpoc
```

2. Serve NFS on loopback:

```bash
agentfs serve nfs labpoc --bind 127.0.0.1 --port 11111
```

3. From any local process, run the raw RPC client:

```bash
python3 pocs/nfs_traversal_capture.py \
  --name /etc/passwd --read 256 --uid 0 --gid 0 \
  --outdir captures/absolute-etc-passwd
```

Expected: MOUNT `/` succeeds; LOOKUP `/etc/passwd` returns `NFS3_OK`; READ returns the first
bytes of host `/etc/passwd`. Traversal variants (`../outside_secret.txt`,
`../../../../etc/passwd`) and a mode-600 server-owned file are captured under `evidence/`.

## Scope

- **Affected:** `agentfs serve nfs`/`agentfs nfs` in overlay mode where `fs_overlay_config.base_path` is set.
- **Not affected:** direct mode (`Mode: direct AgentFS`) — no `HostFS`; FUSE mounts — kernel resolves path components before LOOKUP; ptrace sandbox — mounts `SqliteVfs` only.
- **Write impact:** not confirmed. Overlay mutations are redirected to the SQLite delta layer; the proven primitive is host file read/stat plus copy-up side effects.

## Evidence

| Path | Contents |
|---|---|
| `cve-submission/advisory.md` | Full advisory: metadata, description, PoC, impact, fix |
| `cve-submission/attack-path-simple.md` | Plain-language attack narrative |
| `cve-submission/attacker-cost.md` | Attacker economics and access model |
| `cve-submission/range-verification.txt` | Version scope notes |
| `cve-submission/pocs/nfs_traversal_capture.py` | Raw RPC/NFSv3 capture client |
| `cve-submission/pocs/nfs_traversal_poc.py` | Minimal interactive PoC |
| `pocs/` | Same PoCs at repo root |
| `evidence/captures/` | Record-marked request/response binaries + `result.json` per scenario |
| `evidence/wire_hex_*.txt` | `xxd` dumps of key request/response records |
| `evidence/source_snippets.txt` | Relevant source excerpts |
| `evidence/environment.txt` | UTC, uname, binary hash, git state, listener |
| `evidence/SHA256SUMS.txt` | SHA-256 manifest for evidence and PoCs |
| `report_20261123_181454.md` | Full standardized assessment report |
| `cve-submission/MANIFEST.txt` | sha256 of the submission pack |

## Disclosure

Pending. No CVE assigned yet. Vendor notification not yet sent.
