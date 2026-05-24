# Git Workflow — Branch Protection and Solo Maintainer Model

**Date:** 2026-05-24  
**Context:** Runbound is a solo-maintainer AGPL-3.0 project. There is one contributor with merge rights.

---

## Current configuration

Branch `main` is protected with:

- Force push: disabled
- Branch deletion: disabled
- Required PR reviews: 1 approval
- `enforce_admins`: **true**

## The contradiction

With `enforce_admins=true` and 1 required approval, the sole maintainer cannot merge their own PRs without external approval. This was encountered during PR #105: enforce_admins was temporarily disabled, the merge executed with `--admin`, then enforce_admins re-enabled. This workaround is:

- Functional but manual
- Creates a window (between disable and re-enable) where main is less protected
- Not documented, easy to forget

## Scenario assessment

**This is Scenario B** — enforce_admins is correctly configured and does block the maintainer. The temporary disable-merge-reenable pattern is the current workaround.

## Options

| Option | Description | Verdict |
|--------|-------------|---------|
| (i) Temporary disable/reenable | Current approach | Workable but manual and error-prone |
| (ii) Second GitHub account for approvals | Bot account with reviewer rights | Overhead for solo project; bot approvals provide no real security value |
| (iii) Required approvals = 0, keep other protections | No review gate, but no force-push/no-delete | Honest for solo project |
| (iv) Wait for external human reviewer | Not viable for solo project | Not recommended |

## Recommendation

**Option (iii)** — Set `required_approvals` to 0, keep all other protections active:

- No force-push to main
- No branch deletion
- Require status checks (when CI is configured)
- `enforce_admins: true` (applies status checks and other rules to maintainer too)

**Why:** The 1-approval requirement provides no meaningful protection when the sole reviewer is the same person as the sole submitter. The valuable protections — no force-push, no deletion, CI gates — do not depend on PR approval count. Setting approvals to 0 is honest: it documents that there is no external review process, rather than pretending there is one while bypassing it every merge.

**When to revisit:** If a second regular contributor joins, add the 1-approval requirement then.

## Current status

The recommendation above requires **maintainer decision before any config change**. The current configuration (enforce_admins=true, 1 required review) remains in place until the maintainer confirms which option to adopt.

To implement Option (iii) once approved:

```bash
# Disable enforce_admins temporarily to allow the config change
curl -X DELETE -H "Authorization: Bearer $GH_PAT" \
  https://api.github.com/repos/redlemonbe/Runbound/branches/main/protection/enforce_admins

# Update protection: required_approvals = 0
curl -X PUT -H "Authorization: Bearer $GH_PAT" \
  -H "Content-Type: application/json" \
  https://api.github.com/repos/redlemonbe/Runbound/branches/main/protection \
  --data '{
    "required_status_checks": null,
    "enforce_admins": true,
    "required_pull_request_reviews": {
      "required_approving_review_count": 0
    },
    "restrictions": null,
    "allow_force_pushes": false,
    "allow_deletions": false
  }'
```

**This block is not executed.** Waiting for maintainer approval.
