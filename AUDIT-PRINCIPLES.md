# SECURITY AUDIT REPORTING — MANDATORY CONVENTIONS

This document defines how security audit reports MUST be written for this project. These rules are non-negotiable and override default LLM tendencies toward over-positivity, completeness theater, and category inflation.

The audit reports produced by this project will be read by external security professionals (Cloudflare, NLnet Labs, ISC, independent pentesters). Anything that signals "AI-generated marketing" instead of "rigorous technical audit" destroys credibility. These conventions exist to prevent that.

## CORE PRINCIPLE

A security audit report is NOT a sales document. It is a transparent record of what was checked, what was found, what was fixed, what remains open, what was accepted, and what was NOT checked. Reports that present projects as flawless are immediately distrusted by competent reviewers. Reports that document real limitations build trust.

When in doubt: under-claim, over-disclose.

## RULE 1 — HONEST LABELING OF AUDIT SOURCES

Every audit cycle MUST be labeled with one of these exact tags:

- [AI-INTERNAL] — performed by an AI agent operating under maintainer direction. Default for almost everything in this project today.
- [AI-ADVERSARIAL] — performed by an AI agent specifically prompted in adversarial mode, ideally from a different model family than the implementer. Still AI, but with explicit adversarial framing.
- [HUMAN-EXTERNAL] — performed by a named human individual or organization external to the project, with their name or organization documented.
- [AUTOMATED-TOOL] — performed by a deterministic tool (cargo-audit, Semgrep, CodeQL, etc.) — the tool MUST be named with its version.

Forbidden terms unless they meet the exact definition above:
- "External pentest" → use [AI-ADVERSARIAL] or [HUMAN-EXTERNAL]
- "Live pentest" → use [AI-ADVERSARIAL] with date, or [HUMAN-EXTERNAL]
- "Independent audit" → ONLY for [HUMAN-EXTERNAL]
- "Third-party review" → ONLY for [HUMAN-EXTERNAL]

If a cycle was performed by AI but reviewed/triaged by the human maintainer afterward, the cycle is still [AI-*]. Human triage does not promote an AI audit to human audit status.

This labeling MUST appear in the cycle header, in the Executive Summary table, and in each finding's metadata.

## RULE 2 — SEVERITY CALIBRATION

Severity ratings MUST follow this strict definition. Reports that inflate severity to look impactful are worse than honest "low" ratings.

- CRITICAL — Exploitable remotely without authentication, OR completely defeats a documented security guarantee (DNSSEC bypass, auth bypass, RCE).
- HIGH — Exploitable with authentication, OR results in silent data corruption / integrity loss, OR enables practical DoS from a single source.
- MEDIUM — Reduces defense-in-depth, exploitable under specific preconditions an attacker may or may not have.
- LOW — Best-practice deviation, hardening gap, no direct exploit path.
- INFO — Architectural observation operators should know about. Not a vulnerability.

Forbidden inflations:
- Code quality issues, refactors, dead code → NOT in security audit. File separately under docs/code-quality.md.
- Documentation bugs (typos, wrong port numbers, missing sections) → NOT in security audit. File separately under docs/documentation-fixes.md.
- Missing test coverage → NOT in security audit. File separately under docs/test-coverage.md.
- Performance regressions → NOT in security audit. File separately under docs/performance-issues.md.

If a finding is genuinely both code-quality AND security (e.g., a panic via unwrap() in a request handler that crashes the worker), it stays in security audit but only because of the security impact, not because of the unwrap() itself.

## RULE 3 — FINDING COUNT INTEGRITY

The total finding count is a number reviewers will judge. Do not inflate it.

- Each finding MUST represent a distinct vulnerability class. Splitting one bug into three findings to inflate the count is forbidden.
- Each finding MUST have a documented exploit path or threat model. If you cannot describe HOW it could be exploited (even theoretically), it's not a security finding.
- "Defense in depth" findings are valid but MUST be tagged explicitly: [DEFENSE-IN-DEPTH] after the severity. These mitigations don't fix exploitable bugs; they reduce blast radius if other defenses fail.

Reports showing "N findings, N closed" with N being suspiciously round trigger immediate distrust. Aim for honest finding counts even if lower. 30 real findings beat 60 inflated findings.

## RULE 4 — RESOLUTION STATUS HONESTY

Every audit cycle MUST have findings in multiple status categories. Audits where 100% of findings are "fixed" trigger immediate suspicion of either post-rationalization or filtering.

Required status categories:
- Fixed in vX.Y.Z — code change closes the issue
- Mitigated in vX.Y.Z — partial fix or operational guidance, with residual risk documented
- Accepted risk — known limitation with explicit rationale; MUST link to a section explaining why it's accepted
- Open — targeted vX.Y.Z — not yet fixed, with planned version
- Won't fix — explicit decision not to address, with rationale
- Disputed — finding where auditor and maintainer disagree on severity or validity; both positions documented

If a report has zero entries in Accepted risk, Open, Won't fix, or Disputed, the report is incomplete. Real audits ALWAYS have some of these. Force yourself to identify them. If you genuinely cannot, explicitly state in the executive summary: "This audit identified no accepted-risk or deferred items, which is unusual and may indicate incomplete coverage."

## RULE 5 — EXECUTIVE SUMMARY TONE

The executive summary MUST follow this structure:

"This audit cycle [AI-INTERNAL / AI-ADVERSARIAL / HUMAN-EXTERNAL] reviewed [scope] between [dates]. Methodology: [specific methodology, not just 'manual review']. Findings: N total — [breakdown by severity]. Status: N fixed, N mitigated, N open, N accepted, N disputed, N won't fix. Scope limitations: [what was NOT audited], [what depth of analysis was applied], [what threat models were considered vs not]. Notable observations: [strengths — max 2-3 bullets], [weaknesses or categories needing attention — at least as many bullets as strengths], [areas where the audit could not reach definitive conclusions]. This audit is [AI-INTERNAL / etc.] and does NOT substitute for external human security review. External human audit is [planned for vX.Y / not yet scheduled / completed by NAME on DATE]."

Forbidden phrases in executive summaries:
- "Well-engineered"
- "Robust"
- "Production-ready" (unless [HUMAN-EXTERNAL] specifically signs off)
- "Battle-tested"
- "Industry-leading"
- "Best-in-class"
- "Nation-state grade", "Military-grade"
- Any superlatives

The executive summary describes findings, not the maintainer. The reader will form their own opinion from the substance.

## RULE 6 — PER-FINDING FORMAT

Each finding MUST follow this exact structure:

- ID and concise title
- Severity (one of CRITICAL/HIGH/MEDIUM/LOW/INFO, optionally DEFENSE-IN-DEPTH)
- Source ([AI-INTERNAL / AI-ADVERSARIAL / HUMAN-EXTERNAL / AUTOMATED-TOOL: name])
- File (exact path)
- Discovered (vX.Y.Z)
- Status (Fixed/Mitigated/Open/Accepted/Won't fix/Disputed, with version)
- Threat model: who could exploit this, with what access level, to what effect
- Description: technical description of the vulnerability
- Exploit path: step-by-step how this could be exploited, or "Theoretical — no concrete exploit demonstrated"
- Fix (if applicable): what was changed, with code reference or commit hash
- Residual risk: what remains after the fix. If "none", explicitly say "Fix is believed complete; no known residual risk under the current threat model." Never imply absolute safety.
- Verification: how the fix was verified — unit test, integration test, manual test, re-audit. If "not yet verified", say so.

The Verification field is mandatory. Findings marked "Fixed" without verification evidence are not actually fixed — they are "claimed fixed".

## RULE 7 — METHODOLOGY DISCLOSURE

Every audit cycle MUST include a methodology section that answers:
- What files / modules were reviewed?
- What files / modules were NOT reviewed and why?
- What tools were run? (with versions)
- What threat models were considered?
- What threat models were NOT considered? (e.g., "Side-channel attacks via CPU cache timing not evaluated")
- Time spent on the audit (rough estimate)
- For AI audits: which model, which adversarial prompt, was the implementer model also the auditor model?

This section MUST be at the START of each cycle, not buried at the end.

## RULE 8 — KNOWN LIMITATIONS SECTION

Every security-audit.md MUST contain a top-level section titled "Known Limitations and Accepted Risks". This section lists, at minimum:
- Audit methodology limitations (e.g., "All audits to date have been AI-assisted; external human audit is pending")
- Threat models not yet evaluated (e.g., "Side-channel attacks", "Supply chain attacks beyond cargo-audit", "Fault injection")
- Architectural decisions with security trade-offs
- Operational dependencies (e.g., "DNSSEC validation requires explicit operator enablement")
- Scale at which the system has NOT been tested

If this section is empty or has fewer than 5 entries, the audit is incomplete by definition. Force yourself to find them. Limitations MUST be specific to this project — generic limitations that apply to any project (e.g., "software may contain undiscovered vulnerabilities") are forbidden.

## RULE 9 — VERSION CLAIMS

When stating "Fixed in vX.Y.Z":
- The commit hash containing the fix MUST be linkable
- The test that verifies the fix MUST be linkable (if a test exists)
- If no test exists, state "No automated test; verified by manual review"

Forbidden: claiming fixes without traceable evidence.

## RULE 10 — RE-AUDIT INDEPENDENCE

When re-auditing a previous fix:
- The re-audit MUST be performed by a different agent session than the one that wrote the fix, OR by a human
- The re-audit MUST attempt to break the fix, not just confirm it
- A finding marked "verified fixed" by the same agent that wrote the fix is NOT verified — it's claimed fixed by the same party

If only one model family is available, use separate sessions with explicitly adversarial prompts for the re-audit, and document honestly that implementer and re-auditor share a model family.

## RULE 11 — FORBIDDEN NUMERICAL CLAIMS

Without [HUMAN-EXTERNAL] verification, the following claims are forbidden:
- "Production-ready"
- "Nation-state grade" / "Nation-state ready"
- "Military-grade"
- "Audit-passed" without specifying who audited
- "Zero known vulnerabilities" (always say "no known vulnerabilities under the documented threat model and audit scope")
- "100% test coverage" of anything security-relevant without code coverage metrics linked
- "Hardened" — describe what was hardened against what, don't use the word as a label

These are marketing claims, not audit findings.

## RULE 12 — TASK ON RECEIVING THIS DOCUMENT

When this document is first loaded by an agent, the agent MUST:
1. Re-read the current docs/security-audit.md in full
2. Identify every violation of Rules 1-11
3. Produce a remediation plan (NOT yet applied) listing each violation with its location and proposed correction
4. Present the plan to the maintainer for approval
5. Apply corrections only after explicit approval, one commit per rule category for traceability

Do NOT silently rewrite the audit on first read. The maintainer reviews the plan first.

## ENFORCEMENT

These rules apply to every future audit cycle and to the rewrite of all historical cycles in the current audit document. Future audits that violate these rules MUST be flagged by the agent itself before publication.

If the maintainer overrides any rule for a specific document, the override applies only to that document, NEVER to the security-audit.md file.

End of conventions.
