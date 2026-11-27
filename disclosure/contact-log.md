# Disclosure contact log — agentfs AFS-NFS-01

Target: `tursodatabase/agentfs` @ `v0.6.4` (`3a5ed2b88e5d5a5f9b2c7fe02d012b50fd19e3c0`); `0a014eb` has identical vulnerable files.
Channel: `security@turso.tech` per `https://turso.tech/.well-known/security.txt` — the repo has no `SECURITY.md` and GitHub private vulnerability reporting is disabled.

| # | Contact | Address | Purpose | Status | Date (UTC) | Reference |
|---|---------|---------|---------|--------|------------|-----------|
| 1 | Turso security | `security@turso.tech` (cc `info@turso.tech`) | Vendor notice + report + evidence package | sent | 2026-11-23T20:40:10Z | Message-ID `<gEF5WfS9UfM_wLoDJirvxWqJ8o_Rp8_cqvXqUBV6iMqWtPwHLfV5g9idDXyqB04S0UszLQcLJPe2bjlWsH5BsTbyt4qRZ5pNjMswgj8vKgk=@protonmail.com>`; raw copy [`sent/20261123T204010Z-vendor-security-report-agentfs-nfs01.eml`](sent/20261123T204010Z-vendor-security-report-agentfs-nfs01.eml) (sha256 `b12406fb…811b`); attachment `agentfs-cve-submission-20261123.zip` sha256 `bc1982040cc3ece2a293066870446d4bd6cd2a2ec1d94c546dde8fd2a6765999` |
| 2 | Turso support auto-ack | ticket `TUR-277` | Automated acknowledgement from generic support queue | received; recorded | 2026-11-23T20:41Z | Recorded in [`../cve-submission/report_20261123_181454.md`](../cve-submission/report_20261123_181454.md#disclosure-timeline-utc) |
| 3 | Turso security routing | ticket `TUR-277` | Clarification reply requesting security-team routing | sent; recorded | 2026-11-23T20:44Z | Recorded in [`../cve-submission/report_20261123_181454.md`](../cve-submission/report_20261123_181454.md#disclosure-timeline-utc) |
| 4 | VulnCheck | web form / `disclosure@vulncheck.com` | CVE assignment request for AFS-NFS-01 | pending | — | Package draft: [`../submission/vulncheck/timeline.md`](../submission/vulncheck/timeline.md) |

## Sent package

- Attachment: `agentfs-cve-submission-20261123.zip`
- Zip SHA-256: `bc1982040cc3ece2a293066870446d4bd6cd2a2ec1d94c546dde8fd2a6765999`
- Contents: `advisory.md`, `attack-path-simple.md`, `attacker-cost.md`, `range-verification.txt`, `build-patch-v064.diff`, `MANIFEST.txt`, `report_20261123_181454.md`, and `pocs/` (NFS traversal/enum/db-read/exhaust/crash clients)
- Report repo: <https://github.com/Teycir/agentfs-cve> — public since 2026-11-24T20:38:47Z

## Vendor expectations

- No `SECURITY.md` in `tursodatabase/agentfs`; GitHub private vulnerability reporting is disabled.
- Published channel is `security@turso.tech` per `https://turso.tech/.well-known/security.txt`.
- No vendor acknowledgement window was located; timing remains flexible and deferred to the vendor/CNA.

## Watch items

- [ ] Vendor security-team acknowledgement / routing confirmation
- [ ] VulnCheck submission for AFS-NFS-01 — record case ID here and in `submission/vulncheck/timeline.md`
- [ ] CVE/GHSA assignment — update `README.md`, `report.md`, and this log if assigned
- [ ] Fix release — re-verify against PoCs before any further public disclosure
- [ ] Disclosure timing — flexible, deferred to vendor/CNA; no fixed-day embargo
