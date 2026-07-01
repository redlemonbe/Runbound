# Git Workflow — Branch Protection and Solo Maintainer Model

**Date:** 2026-05-24 (superseded 2026-07-01 — Option (iii) below is now live)  
**Context:** Runbound is a solo-maintainer AGPL-3.0 project. There is one contributor with merge rights.

---

## Current configuration (verified live via `gh api .../branches/main/protection`)

Branch `main` is protected with:

- Force push: disabled
- Branch deletion: disabled
- Required PR reviews: **none** (`required_pull_request_reviews` unset)
- `enforce_admins`: **false**

This is Option (iii) below, now implemented. The maintainer merges PRs directly (see #211, #207, #200, #198, #189 — all merged without the disable/re-enable dance).

## The contradiction (historical — resolved)

Previously, with `enforce_admins=true` and 1 required approval, the sole maintainer could not merge their own PRs without external approval. This was encountered during PR #105: enforce_admins was temporarily disabled, the merge executed with `--admin`, then enforce_admins re-enabled. This workaround was:

- Functional but manual
- Created a window (between disable and re-enable) where main was less protected
- Not documented, easy to forget

## Scenario assessment (historical)

**This was Scenario B** — enforce_admins was correctly configured and did block the maintainer. The temporary disable-merge-reenable pattern was the workaround at the time.

## Options (considered 2026-05-24)

| Option | Description | Verdict |
|--------|-------------|---------|
| (i) Temporary disable/reenable | Previous approach | Workable but manual and error-prone |
| (ii) Second GitHub account for approvals | Bot account with reviewer rights | Overhead for solo project; bot approvals provide no real security value |
| (iii) Required approvals = 0, keep other protections | No review gate, but no force-push/no-delete | Honest for solo project — **adopted** |
| (iv) Wait for external human reviewer | Not viable for solo project | Not recommended |

## Recommendation (adopted)

**Option (iii)** — `required_approvals` = 0, other protections active:

- No force-push to main
- No branch deletion
- `enforce_admins: false` — the maintainer merges directly; no disable/re-enable workaround needed anymore

**Why:** The 1-approval requirement provided no meaningful protection when the sole reviewer was the same person as the sole submitter. The valuable protections — no force-push, no deletion — do not depend on PR approval count. Approvals = 0 is honest: it documents that there is no external review process, rather than pretending there is one while bypassing it every merge.

**When to revisit:** If a second regular contributor joins, add a required-approval count then, and reconsider `enforce_admins: true` at that point.

## Current status

Live as of 2026-07-01: `enforce_admins: false`, no required PR reviews, force-push and branch deletion still disabled. No further action needed unless a second contributor joins.
