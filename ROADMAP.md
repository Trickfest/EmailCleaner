# ROADMAP

## Feature Backlog (Unordered)

No implied priority order. Items below are features to consider implementing.

- [ ] Scheduling support for periodic runs (15/30 minute cadence) with clear setup docs (`cron`, `launchd`, `systemd`) and safe defaults.
- [ ] Run lock / overlap guard to prevent concurrent scheduled executions from racing against each other.
- [ ] False-positive recovery flow (easy restore from `Quarantine` and one-step sender/domain allowlisting).
- [ ] Reliability hardening for IMAP and OpenAI calls (timeouts, bounded retries, fail-safe keep behavior on uncertainty).
- [ ] Operational visibility with structured logs, concise per-run summary, and meaningful non-zero exit codes on failure.
- [ ] Config validation mode (for account/rules/OpenAI config) before first production run.
- [ ] OpenAI usage guardrails (per-run budget cap and clear fallback when cap is hit).
- [ ] Regression corpus of sanitized fixtures from real spam/ham to protect precision and recall across updates.
- [ ] Add additional provider support, starting with iCloud.
- [ ] Email report summaries so behavior is visible without accessing the server.
- [ ] Email report summary cadence option: default one digest every 24 hours.
- [ ] Email report summary cadence option: optional 12-hour digest.
- [ ] Email reports should include only aggregate counts and compact examples (no full message bodies).
- [ ] Email reports should include errors/warnings and top matched rules for auditability.

## Notes
- Deterministic rules are still useful even with strong LLM performance: they reduce cost/latency and provide resilience when API calls fail.
- Keep privacy posture strict in reporting and logs: avoid exposing full message bodies.
