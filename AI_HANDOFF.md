# AI work log and handoff

## Active handoff - 2026-10-30 - Codex - v1.19.32-dm5 preparation; NO repeated tests

Owner explicitly authorizes publishing all completed Mihomo/V2bX changes with
new versions without rerunning tests. Fresh isolated clean clone at56a788a3,
doctormobile, latestv1.19.32-dm4; all open PRs queried (none). PRs6/7/8 already
merged, implementation authored by Claude. Existing Android run41082113085 and
managed-server run41080512115 are successful; these were inspected, not rerun.

Codex release-only edits, UNCOMMITTED / NOT RELEASED:
- .github/workflows/release-dm.yml: dispatch tag/notes, same10target binaries
  andwith_gvisor/version flags, Go1.25, NDKr28for2CGOAndroid targets; no tests.
  Every build must succeed before SHA256SUMS and draft creation/upload/publish.
  GITHUB_TOKEN publication avoids tag-triggered duplicate tests/builds.
- docs/releases/v1.19.32-dm5.md: HTTP auth, liveMieru/ShadowQUIC membership,
  uniqueMieruUDPsource, managedSudoku/Snell and source address fixes.
- AI_HANDOFF.md: this entry; shared Hiddify handoff also updated.

YAML parsing, ten-target matrix and publication dependency checks PASS;
git diff --check PASS. actionlint is not installed (tool lookup returned1),
so no actionlint result claimed. Actual10builds/assets PENDING. No tests run.
No app update/server deployment; existing mihomo-fork and Hiddify work preserved.
CompanionV2bXPR23 merged forv1.11.0; its prior fullstack report has2MDNS
environment-address-clash failures (371/373), not freshly validated here.
