# Disclosure timeline — agentfs AFS-NFS-01 (UTC)

| Time | Event | Proof / contact artifact |
|---|---|---|
| 2026-11-23T18:05:28Z–19:16:49Z | PoC verification on `agentfs` built from upstream `v0.6.4` tag source (`3a5ed2b`); traversal, absolute-path, mode-600 uid spoof, enumeration, DB/WAL read, copy-up exhaustion, and OOM crash reproduced | [`../../cve-submission/report_20261123_181454.md`](../../cve-submission/report_20261123_181454.md) · [`../../evidence/captures/`](../../evidence/captures/) |
| 2026-11-23T20:05:57Z–20:06:18Z | Listener-correlated kernel OOM kill of the `agentfs serve nfs` PID after 1-byte READ of a 1 TB sparse file | [`../../evidence/captures/v064-crash-oom/`](../../evidence/captures/v064-crash-oom/) |
| 2026-11-23T20:40:10Z | Vendor report emailed to `security@turso.tech` (cc `info@turso.tech`), subject `Security vulnerability report: agentfs serve nfs path traversal → arbitrary host file disclosure + server crash (AFS-NFS-01)`; attachment `agentfs-cve-submission-20261123.zip` sha256 `bc1982040cc3ece2a293066870446d4bd6cd2a2ec1d94c546dde8fd2a6765999`; Message-ID `<gEF5WfS9UfM_wLoDJirvxWqJ8o_Rp8_cqvXqUBV6iMqWtPwHLfV5g9idDXyqB04S0UszLQcLJPe2bjlWsH5BsTbyt4qRZ5pNjMswgj8vKgk=@protonmail.com>` | [`../../disclosure/sent/20261123T204010Z-vendor-security-report-agentfs-nfs01.eml`](../../disclosure/sent/20261123T204010Z-vendor-security-report-agentfs-nfs01.eml) |
| 2026-11-23T20:41Z | Turso support auto-ack received; generic ticket `TUR-277` | Recorded in [`../../cve-submission/report_20261123_181454.md#disclosure-timeline-utc`](../../cve-submission/report_20261123_181454.md#disclosure-timeline-utc) and [`../../disclosure/contact-log.md`](../../disclosure/contact-log.md) |
| 2026-11-23T20:44Z | Clarification reply sent on `TUR-277` identifying this as a security report for open-source `agentfs` and requesting routing to the security team | Recorded in [`../../cve-submission/report_20261123_181454.md#disclosure-timeline-utc`](../../cve-submission/report_20261123_181454.md#disclosure-timeline-utc) and [`../../disclosure/contact-log.md`](../../disclosure/contact-log.md) |
| 2026-11-27T18:31:14Z | VulnCheck disclosure for AFS-NFS-01 — case `09cfc547-ec96-4c0f-a469-48823a8137b1` | VulnCheck case `09cfc547-ec96-4c0f-a469-48823a8137b1` |
| 2026-11-27T18:31:14Z | Report repository `Teycir/agentfs-cve` made public manually after VulnCheck submission as the reproduction package | <https://github.com/Teycir/agentfs-cve> |

## Vendor channels used

1. `security@turso.tech` — primary channel per `https://turso.tech/.well-known/security.txt` (repo has no `SECURITY.md`; GitHub private vulnerability reporting disabled).
2. `info@turso.tech` — cc on the initial report.

No fixed-day embargo is proposed anywhere in this package. Disclosure timing is flexible and deferred to the vendor/CNA.
