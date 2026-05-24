# How Runbound was built

I'm not a software engineer by training. My background is ASM, PHP, HTML — hardware and networks are where I'm most comfortable. Self-taught on Linux Debian, Nginx, Proxmox, SMTP. I learned the basics of Rust in a few hours, enough to read and understand it, not enough to write it from scratch.

This project started from frustration: I was tired of editing Unbound config files by hand every week. The original idea was just a REST API wrapper around Unbound. Then I realized that with the right prompts, I could go much further.

By v0.2 the benchmark numbers were surprising enough that I made a decision: build a real DNS server, not a wrapper. Build what sysadmins dream about but never dare ask for.

---

## The workflow

Three specialized AI agents, each with a single role:

| Agent | Role |
|---|---|
| **Coder** | Translates architecture decisions into Rust |
| **Pentester** | IA audit testing — API, DNS, memory, privilege escalation |
| **Code auditor** | Security audit, constant-time checks, no shortcuts |

**External review** — Gemini used as a second opinion on architecture and project direction. No AI is fully neutral, but the disagreements were informative.

**My role: orchestra conductor.** I hold the vision, ask the right questions, validate the results, and decide what gets shipped.

AI tools are used at multiple stages: implementation, adversarial review, and test generation. All security-critical findings are triaged by the maintainer. External human security review is planned before v1.0.

---

This is not "AI wrote my code." This is a new way to build — where domain expertise and system intuition drive the architecture, and AI handles the translation into syntax.

*Just for fun — and because the first benchmark results were too good to keep to myself.*
