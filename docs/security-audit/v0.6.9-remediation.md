# Security Audit Remediation Plan

**File analyzed:** docs/security-audit.md  
**Analyzed against:** AUDIT-PRINCIPLES.md Rules 1–11  
**Date:** 2026-05-24  
**Status:** PLAN — awaiting maintainer approval before any rewrite

---

## Summary

| Metric | Count |
|--------|-------|
| Total SEC findings reviewed | 11 (SEC-01 through SEC-11) |
| Total PERF items in document | 10 (PERF-01 through PERF-10) |
| Rule violations identified | 38 distinct violations across Rules 1–11 |
| Findings to reclassify as non-security | 10 (all PERF items + §3.9 R4 NUMA) |
| Source attribution violations (R1) | 14 (header + exec summary + 11 findings + §3.9 table + conclusion) |
| Forbidden phrases (R5/R11) | 5 occurrences |
| Findings missing mandatory fields (R6) | 11 findings × 6 missing fields = 66 field gaps |
| Sections entirely absent | 2 (Methodology §R7, Known Limitations §R8) |

---

## Violations by Rule

### Rule 1 — Honest Labeling of Audit Sources

**14 instances of missing or incorrect source labels:**

1. **Header (line 1–6):** No `[AI-INTERNAL]` cycle tag. The document has no cycle identification.
2. **§1 Executive Summary (line 9–14):** No source label. Structure does not match the mandatory template.
3. **§3.2 verdict (line 81):** `"✅ HSM-compliant"` — implies external compliance certification. Should state the claim is based on code review only, labeled [AI-INTERNAL].
4. **§3.1 verdict (line 68):** `"Compliant with ANSSI secure API guidelines"` — implies ANSSI external review. Forbidden unless [HUMAN-EXTERNAL]. Must reword as "consistent with ANSSI guidelines per AI-internal review."
5. **SEC-01 through SEC-11 (§5, lines 278–292):** None of the 11 findings has a Source field. All must have `[AI-INTERNAL]` added.
6. **§3.9 (lines 169–175):** The §3.9 table (R1–R4) has no source labels per finding.
7. **§7 Conclusion (line 346–348):** Uses "production-ready" as a verdict — implies an authoritative external determination. Source of this verdict is undisclosed.

**Proposed corrections:**
- Add cycle header: `**Audit cycle:** [AI-INTERNAL] — Claude Sonnet 4.6, maintainer-directed, 2026-05-23`
- Add Source field to all 11 SEC findings in §3 and §5
- Replace ANSSI/HSM compliance verdicts with scoped claims: "consistent with [standard] based on [AI-INTERNAL] code review"
- Remove authoritative-sounding verdicts without qualification

---

### Rule 2 — Severity Calibration

**4 violations:**

1. **§3.9 R3 (line 173):** `LOW/GDPR` — GDPR is not a severity level. Severity must be one of CRITICAL/HIGH/MEDIUM/LOW/INFO. Correct to `LOW` with a note: "GDPR-relevant: if IP logging retention is legally restricted."
2. **§3.9 R4 (line 174):** `No NUMA awareness — LOW` — NUMA awareness is a performance optimization, not a security finding. Must be moved to docs/performance-issues.md (see "Findings to move" section). PERF-03 in §4.3 already covers this.
3. **§3.6 verdict (line 143):** `"Verdict: ✅ Robust."` — "Robust" is explicitly forbidden. Must be removed or replaced with a factual summary of what was verified.
4. **§4 Performance Audit (lines 178–305):** The entire Performance Audit section violates Rule 2 by including PERF-01 through PERF-10 in a security audit document. Performance regressions belong in docs/performance-issues.md.

---

### Rule 3 — Finding Count Integrity

**3 violations:**

1. **PERF-01 through PERF-10 in §5 matrix (lines 296–306):** 10 performance findings inflate the security audit count. §5 is titled "Consolidated Risk Matrix" but mixes security and performance. The security count should be 11; the document conflates 11 SEC + 10 PERF = 21 entries as a single "risk matrix."
2. **§3.9 R4 duplicate (line 174):** NUMA finding appears as both security item R4 in §3.9 AND as PERF-03 in §4.3 and §5. Duplicate finding in two categories.
3. **§3.9 table vs §3 findings:** §3.9 R1–R4 appear as additional risk items without SEC-IDs, then SEC-01–11 appear in §5. The relationship between R1–R4 and SEC-01–11 is ambiguous — SEC-05 (DNSSEC) maps to R2, SEC-06 (privilege) maps to R1, but the mapping is not explicit. This creates apparent count inflation.

---

### Rule 4 — Resolution Status Honesty

**Critical violations:**

1. **§5 Security matrix (lines 278–292):** Of 11 SEC findings: 8 are ✅ Fixed, 3 are ⚠️ Open. Zero entries in Accepted risk, Won't fix, or Disputed categories. This is explicitly prohibited by Rule 4.
2. **SEC-03 UMEM (lines 96–112):** Marked ✅ Fixed via `checked_add`. However, the text states "Kernel trust is implicit (acceptable for dedicated hardware deployment)" — this is an accepted risk that must be labeled as such, not "Fixed." The fix addresses integer overflow; the underlying kernel trust assumption remains an accepted risk.
3. **SEC-05 DNSSEC (lines 141–142, 285):** Marked ⚠️ Open but no targeted version (e.g., "Open — targeted v1.0"). Missing mandatory version tag.
4. **SEC-06 Privilege dropping (lines 171–172, 286):** Same issue — ⚠️ Open with no targeted version.
5. **SEC-04 HTTP body cap (line 283):** Listed as ✅ Fixed with no commit hash and no verified-by evidence. This is "claimed fixed," not "verified fixed" (see Rule 9).

**Proposed correction:** Identify at minimum one Accepted risk (SEC-03 kernel trust assumption), one deferred item with version target, and review whether any finding qualifies as Won't fix.

---

### Rule 5 — Executive Summary Tone

**5 violations:**

1. **§1 line 11:** `"Runbound is architecturally sound for production deployment."` — evaluative claim, forbidden framing.
2. **§1 line 13:** `"Overall verdict: production-ready with four blocking items."` — "production-ready" is explicitly forbidden without [HUMAN-EXTERNAL] sign-off.
3. **§3.6 line 143:** `"Verdict: ✅ Robust."` — "Robust" is explicitly forbidden.
4. **§1:** Missing the mandatory structure: no scope limitations, no "This audit is [AI-INTERNAL] and does NOT substitute for external human security review," no "External human audit is [not yet scheduled]."
5. **§7 line 347:** `"Runbound v0.6.9 is production-ready pending the four blocking items above."` — second "production-ready" in the conclusion.

**Proposed correction:** Rewrite §1 following the mandatory template from AUDIT-PRINCIPLES.md §Rule5 verbatim. Rewrite §7 to remove evaluative verdict.

---

### Rule 6 — Per-Finding Format

**66 field gaps across 11 findings:**

Each of SEC-01 through SEC-11 is missing these 6 mandatory fields:
- Source (all 11 findings)
- Discovered vX.Y.Z (all 11 findings)
- Threat model (all 11 findings)
- Exploit path (all 11 findings — some have partial descriptions but not the step-by-step format)
- Residual risk (all 11 findings)
- Verification (all 11 findings)

**Currently, the format used is:**
- Brief description paragraph
- Code snippet (some)
- Single-line verdict

This format does not meet the mandatory 12-field structure.

**Proposed correction:** Expand all 11 SEC findings to the full 12-field format (ID, title, severity, source, file, discovered, status, threat model, description, exploit path, fix, residual risk, verification).

---

### Rule 7 — Methodology Disclosure

**Section entirely absent.**

The document has no methodology section. Required content:
- Files reviewed (and files NOT reviewed)
- Tools run with versions (cargo-audit version? clippy version? any fuzzer?)
- Threat models considered (and not considered — e.g., side-channel, supply chain, fault injection)
- Time spent
- AI model used, adversarial prompt strategy, whether implementer = auditor

**Proposed correction:** Add §0 Methodology before §1 Executive Summary.

---

### Rule 8 — Known Limitations Section

**Section entirely absent.**

No "Known Limitations and Accepted Risks" section exists. Minimum 5 project-specific entries required:
- All audits to date are AI-assisted; no external human audit
- Side-channel attacks (timing, cache, EM) not evaluated
- Supply chain attacks beyond cargo-audit (build system, compiler, toolchain) not evaluated
- DNSSEC validation requires explicit operator enablement — security guarantee is conditional
- NUMA/multi-socket deployments not tested; XDP worker affinity assumptions untested at scale
- Fault injection and kernel exploit scenarios (kernel < 5.15 with BTF mismatches) not evaluated

**Proposed correction:** Add §Known Limitations section.

---

### Rule 9 — Version Claims

**5 violations:**

| Finding | Claim | Issue |
|---------|-------|-------|
| SEC-08 (line 154) | "Fixed in v0.6.9" | No commit hash |
| SEC-11 (line 283) | "✅ Fixed v0.6.11" | No commit hash |
| SEC-01 (line 281) | "✅ Mitigated (subtle + sleep)" | No commit hash, no test reference |
| SEC-02 (line 282) | "✅ Zeroizing" | No commit hash |
| SEC-04 (line 283) | "✅ Capped 65 KiB" | No commit hash, no test reference |

**Proposed correction:** Add commit hashes to each "Fixed in vX.Y.Z" claim, or state "No automated test; verified by manual review" explicitly.

---

### Rule 10 — Re-Audit Independence

**2 violations:**

1. The document contains no statement about the independence of any re-audit cycle.
2. Fixes marked "verified" (SEC-03, SEC-08) were verified by the same agent session that produced the report. This is "claimed verified" not "independently verified."

**Proposed correction:** Add to §0 Methodology: "All fixes to date have been verified by [AI-INTERNAL] review in the same session that produced the finding. No independent session re-audit or [AI-ADVERSARIAL] re-audit has been performed. Fixes should be treated as 'claimed fixed, not independently verified.'"

---

### Rule 11 — Forbidden Numerical Claims

**5 occurrences of forbidden phrases:**

| Location | Phrase | Rule |
|----------|--------|------|
| §1 line 13 | "production-ready" | R11 |
| §7 line 347 | "production-ready" | R11 |
| §3.1 line 68 | "Compliant with ANSSI secure API guidelines" | R11 (implies external certification) |
| §3.2 line 81 | "HSM-compliant" | R11 (implies external certification) |
| §3.6 line 143 | "Robust" | R11 |

---

## Findings to Move Out of Security Audit

These items should be removed from docs/security-audit.md and placed in separate documents:

| Item | Current location | Target document |
|------|-----------------|-----------------|
| PERF-01 Cache publish 100 ms | §4.3, §5 | docs/performance-issues.md |
| PERF-02 Mutex on mutable cache | §4.3, §5 | docs/performance-issues.md |
| PERF-03 NUMA awareness | §3.9 R4, §4.3, §5 | docs/performance-issues.md |
| PERF-04 Hugepages optional | §4.3, §5 | docs/performance-issues.md |
| PERF-05 TX batching | §4.3, §5 | docs/performance-issues.md |
| PERF-06 SO_REUSEPORT fallback | §4.3, §5 | docs/performance-issues.md |
| PERF-07 jemalloc | §5 | docs/performance-issues.md |
| PERF-08 CPU affinity | §5 | docs/performance-issues.md |
| PERF-09 IRQ affinity | §5 | docs/performance-issues.md |
| PERF-10 NIC ring | §5 | docs/performance-issues.md |
| §4 Performance Audit (entire) | §4 | docs/performance-issues.md |
| §3.9 R3 GDPR note | §3.9 | docs/documentation-fixes.md (operator note) |

Note: §4 XDP Hot Path Analysis (§4.1) and AF_XDP Configuration (§4.2) are informational architecture notes — they could be preserved in docs/security-audit.md under an "Architecture Context" section since they inform threat model understanding, but the PERF findings themselves must move.

---

## Proposed Final Structure

```
docs/security-audit.md (after remediation)
│
├── §0 Methodology [NEW]
│   ├── Audit cycle identification: [AI-INTERNAL] + date + model
│   ├── Scope: files reviewed, files NOT reviewed
│   ├── Tools: cargo-audit vX.Y.Z, clippy, manual review
│   ├── Threat models considered / not considered
│   ├── Re-audit independence statement
│   └── Time estimate
│
├── §1 Executive Summary [REWRITE]
│   ├── Mandatory structure (AUDIT-PRINCIPLES.md §Rule5)
│   ├── N total findings, breakdown by severity
│   ├── Status breakdown (Fixed/Mitigated/Open/Accepted/Disputed/Won't fix)
│   ├── Scope limitations
│   └── External human audit: not yet scheduled
│
├── §2 Architecture Overview [KEEP, minor edits]
│   └── Remove "Architectural strengths:" label (evaluative)
│
├── §3 Security Findings [EXPAND all 11 to 12-field format]
│   ├── SEC-01 through SEC-11
│   ├── Each with: Source, Discovered, Threat model, Exploit path, Residual risk, Verification
│   └── SEC-03 status: ✅ Partially fixed (overflow check) + Accepted risk (kernel trust)
│
├── §4 Known Limitations and Accepted Risks [NEW]
│   ├── KL-01: All audits AI-assisted, no external human review
│   ├── KL-02: Side-channel attacks not evaluated
│   ├── KL-03: Supply chain beyond cargo-audit not evaluated
│   ├── KL-04: DNSSEC guarantee is conditional on operator enablement
│   ├── KL-05: NUMA/multi-socket deployments untested
│   └── KL-06: Fault injection and kernel exploit scenarios not evaluated
│
├── §5 Consolidated Security Risk Matrix [REVISED]
│   ├── SEC-01 through SEC-11 only
│   ├── Multi-status (not all Fixed)
│   └── Performance items removed
│
└── §6 Priority Recommendations [KEEP, remove perf items]
    └── Remove PERF items; focus on SEC-05, SEC-06, and open items
```

**Removed from security-audit.md:**
- §4 Performance Audit (entire section → docs/performance-issues.md)
- PERF-01 through PERF-10 from §5 matrix
- "production-ready" verdicts (×2)
- "Robust" (×1)

---

## Estimated Effort

| Commit | Description | Effort |
|--------|-------------|--------|
| R1, R7 | Add §0 Methodology + source labels to all findings | Medium |
| R5, R11 | Rewrite §1 Executive Summary + remove forbidden phrases | Medium |
| R6 | Expand SEC-01–SEC-11 to 12-field format | High (11 findings × 6 fields) |
| R2, R3 | Remove §4 Performance section + PERF items from §5 | Low |
| R4, R8 | Add Known Limitations section + fix status categories | Medium |
| R9, R10 | Add commit hashes + independence statement | Low |

**Total: 6 commits** (one per rule category as specified in AUDIT-PRINCIPLES.md §Rule12)  
**Estimated time: 2–3 hours** (primary bottleneck: expanding 11 findings to full 12-field format with accurate commit hashes)

---

## Notes for Maintainer

1. **SEC-03 status change required:** "✅ Fixed" → split into "✅ Partially fixed (overflow check in v0.6.x)" + "Accepted risk: kernel trust assumption for dedicated hardware deployment." This is a material status change the maintainer should explicitly approve.

2. **Performance audit content:** The §4 performance analysis contains genuinely useful content. Recommend preserving it as `docs/performance-analysis.md` rather than deleting it.

3. **Commit hashes for old fixes:** SEC-08 (v0.6.9) and SEC-11 (v0.6.11) need their commit hashes retrieved from `git log`. These are in the repo history.

4. **Verdicts "✅ Compliant with ANSSI":** This was likely AI-generated from training data knowledge of ANSSI guidelines. It has never been externally verified. Recommend rewording to: "implementation is consistent with ANSSI RGS guidelines based on [AI-INTERNAL] code review; no formal ANSSI evaluation has been conducted."

---

*Awaiting maintainer approval before rewriting docs/security-audit.md.*
