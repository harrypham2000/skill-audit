# AI Agent Skill Security Auditing Plan for the Vercel Skills Ecosystem

## Executive Overview

The Vercel **skills** CLI (`npx skills`) is the de facto package manager for the open Agent Skills ecosystem, installing skills from GitHub and other git remotes into agent-specific skills folders. Skills are folders that must contain a `SKILL.md` file with YAML frontmatter (`name`, `description`) and may bundle scripts, references, and other resources that agents can execute or read at runtime. Today, the CLI focuses on discovery and installation (list, find, update) and does **not** perform security auditing of skills before copying them into local or global agent skill directories.[^1][^2][^3]

This plan defines a full-stack **AI Agent Skill Security Auditing** solution that can plug into the Vercel skills ecosystem, providing pre‑install and continuous auditing of skills and their components, aligned with the OWASP Agentic Top 10 and secure SDLC / ISO 27001 practices. It draws on existing tooling like `skill-audit`, `skills-security-audit`, and similar scanners while defining a vendor‑neutral architecture that can be reused across agent platforms.[^4][^5][^6][^7][^8][^9]

***

## 1. Background and Context

### 1.1 Agent Skills and the Vercel Skills CLI

Agent Skills are an open format for extending AI coding assistants and other agents with reusable, file‑based capabilities that load at runtime from `SKILL.md` markdown files. The Vercel **skills** CLI is "the CLI for the open agent skills ecosystem" and supports installing skills to many agents (Claude Code, Codex, Cursor, GitHub Copilot, etc.) into well‑known project or global skill directories. The CLI discovers skills in repositories by scanning common paths such as `skills/`, `.claude/skills/`, `.agents/skills/`, and others, falling back to a recursive search for `SKILL.md` files if needed.[^2][^3][^1]

The Skills Directory at **skills.sh** exposes a public leaderboard and registry of skills from many providers (Vercel, Anthropic, Microsoft, others), making skill installation as simple as `npx skills add owner/repo`. Community documentation and examples describe skill library layouts where each skill folder contains `SKILL.md`, `README.md`, optional `metadata.json`, `rules/`, `scripts/`, and `references/`, and can also be distributed as zip archives.[^10][^11][^12][^2]

### 1.2 Existing Security Guidance for Skills

Anthropic’s Agent Skills documentation explicitly warns that skills are equivalent to installing software and should only be used from trusted sources or after thorough audit of all bundled files (instructions, scripts, images, external URLs). The guidance highlights risks such as malicious skills exfiltrating data, abusing tools (file system, bash, HTTP), or loading hostile content from external endpoints referenced by the skill. This aligns with the OWASP Agentic Top 10, which identifies risks like **Agentic Supply Chain Vulnerabilities (ASI04)**, **Unexpected Code Execution (ASI05)**, and **Tool Misuse (ASI02)** in agent pipelines.[^13][^7][^8][^14]

### 1.3 Existing Skill Auditing Tools

Several open‑source efforts have started to address skill security:

- **skill-audit**: a security auditing CLI for AI agent skills that scans for prompt injection patterns, secrets, dangerous shell usage, and insecure Python/JavaScript code via tools like Semgrep, ShellCheck, and TruffleHog/Gitleaks, emitting SARIF for CI integration.[^5]
- **skills-security-audit**: an AI Agent Skill that semantically analyzes skills for vulnerabilities such as prompt injection, data exfiltration, obfuscated code, privilege escalation, supply chain attacks, memory poisoning, and behavioral manipulation, mapping findings to OWASP Agentic AI Top 10 risk categories.[^15][^4]
- **skill-security-auditor** (marketplace listing): describes a skill that inspects `SKILL.md`, scripts, and references for malicious behavior and vulnerabilities.[^6]

These tools show that both static rule‑based scanners and AI‑assisted semantic analysis are valuable but are not yet tightly integrated into the mainstream `npx skills` installation flow.[^1][^5]

***

## 2. Objectives and Scope

### 2.1 Primary Objectives

- **Pre‑install security gate**: audit skills **before** they are written into project or global skill directories for any agent.
- **Full‑bundle coverage**: analyze not only `SKILL.md`, but also scripts, configuration files, metadata, references, and embedded code snippets.
- **Risk classification and scoring**: assign per‑skill risk scores and severity levels aligned with the OWASP Agentic Top 10 (ASI01–ASI10) and clearly indicate whether a skill is safe, risky, or malicious.[^7][^8]
- **Trust and provenance checks**: validate the skill’s source (repository, owner, signatures), dependencies, and known vulnerabilities from trusted vulnerability databases.
- **SDLC and compliance alignment**: integrate into secure SDLC activities (requirements, design, implementation, verification) and support ISO 27001, OWASP SAMM, and similar frameworks.[^16][^9][^17]

### 2.2 In‑Scope Skill Artifacts

- `SKILL.md` frontmatter and instruction body.
- Auxiliary markdown (`README.md`, `AGENTS.md`, rule markdown) bundled with the skill.[^10]
- Source code and scripts (e.g., `scripts/`, `lib/`, `src/`) in languages such as Bash, Python, JavaScript/TypeScript, etc.[^4][^5]
- Configuration, metadata, and manifest files (e.g., `metadata.json`, `package.json`, `requirements.txt`, `pyproject.toml`).[^2][^10]
- References directory contents, especially files that may influence agent behavior (templates, prompts, data files).[^10]
- External dependencies such as npm packages, PyPI packages, and remote URLs referenced by the skill.

***

## 3. Threat Model and Sources of Trust

### 3.1 Threat Model for Agent Skills

Key risks when installing and using third‑party skills:

- **Agentic Supply Chain Vulnerabilities (ASI04)**: malicious or compromised skills, tools, or descriptors that introduce backdoors, data exfiltration, or privilege escalation into agent workflows.[^8][^14][^7]
- **Unexpected Code Execution (ASI05)**: scripts or commands in skills that perform unsafe or unintended operations (e.g., `curl | sh`, arbitrary code evaluation, `rm -rf`), often triggered under benign‑looking instructions.[^7][^5]
- **Tool Misuse and Exploitation (ASI02)**: skills that guide agents to misuse tools (filesystem, HTTP clients, cloud CLIs) in ways that delete data, leak secrets, or break integrity guarantees.[^13][^7]
- **Memory and Context Poisoning (ASI06)**: skills that introduce deceptive or hostile instructions that persist in context and bias agent reasoning.[^7][^13]
- **Human–Agent Trust Exploitation (ASI09)**: skills that abuse perceived authority to recommend unsafe actions or social‑engineer users into disclosing secrets or approving risky changes.[^8][^7]

### 3.2 Trust and Vulnerability Data Sources

The auditor should rely on multiple sources of trust and telemetry:

- **Repository provenance**: verify that the skill is cloned from a reputable host (GitHub, GitLab) and that the owner and repo are known and not recently compromised (e.g., using GitHub’s security advisories and commit history checks).[^18][^1]
- **Dependency vulnerability databases**: query ecosystems like npm, PyPI, and OSS‑wide databases such as OSV for known CVEs or advisories affecting packages referenced by the skill (e.g., Node packages in `package.json`).[^5]
- **OWASP Agentic Top 10**: use OWASP’s risk categories to classify findings and drive remediation guidance around agentic supply chain, unexpected execution, and tool misuse.[^14][^7][^8]
- **Secure SDLC and ISO 27001 controls**: align the auditing process with SDLC security phases (requirements, design, implementation, verification) and ISO 27001 Annex A controls for secure development (e.g., 8.25–8.28, 8.31).[^9][^19][^16]
- **Existing scanners**: integrate battle‑tested tools (Semgrep, ShellCheck, TruffleHog/Gitleaks) and mapping layers used by projects like `skill-audit`.[^5]

***

## 4. High‑Level Architecture

### 4.1 Components Overview

The proposed architecture consists of the following components:

1. **Skill Ingestion Layer**
   - Accepts a skill source (git URL, shorthand `owner/repo`, local path) exactly as used by `npx skills add`.[^1]
   - Clones or reads the repo into a temporary sandbox (read‑only for local sources).
   - Discovers skills within the repo using the same path logic as the `skills` CLI (`skills/`, `.claude/skills/`, etc.), and enumerates individual skill folders or `SKILL.md` locations.[^1]

2. **Skill Manifest Builder**
   - Builds a structured manifest per skill (e.g., JSON) enumerating metadata, files, script entrypoints, dependencies, external URLs, and tool usage hints from `SKILL.md` and related files.[^3][^2]

3. **Static Analysis Engine**
   - Runs multiple analyzers over the manifest:
     - Prompt and instruction linting (prompt injection, jailbreak patterns, unsafe guidance).[^4][^5]
     - Script and code analysis (Bash, Python, JS/TS) via Semgrep, ShellCheck, and other language‑specific rules.[^5]
     - Secret scanning via TruffleHog or Gitleaks.[^5]
     - Configuration and metadata checks (e.g., broad scopes, unpinned versions, allowed‑tool misuse).[^13][^2]

4. **Dependency and SBOM Analyzer**
   - Generates a Software Bill of Materials (SBOM) for the skill’s code dependencies (npm, PyPI, etc.).
   - Queries vulnerability databases (e.g., OSV, npm audit APIs) to identify known vulnerabilities and severity.

5. **Trust and Provenance Evaluator**
   - Evaluates the source repository: owner reputation, signed releases/tags, presence of security policy, update history.[^18]
   - Optionally verifies signed commits or tags if available.

6. **Policy Engine and Risk Scoring**
   - Normalizes findings into a common schema (ID, category, severity, evidence, remediation suggestion).
   - Maps findings to OWASP Agentic Top 10 categories and aggregates into a numeric risk score (0–10) and level (Safe, Risky, Dangerous, Malicious), similar to the `skills-security-audit` report format.[^15][^4]

7. **Reporting and Export Layer**
   - Produces human‑readable reports (Markdown, HTML) and machine‑readable results (JSON, SARIF) for CI integration.[^4][^5]
   - Supports batch reports summarizing multiple skills with top findings and scores.[^4]

8. **Integration Interfaces**
   - CLI command (e.g., `skills audit`) that can run standalone or as part of `skills add` flow.
   - Node/TypeScript API for other tools and agents to call the auditor programmatically, including as an Agent Skill itself.

### 4.2 Deployment and Execution Modes

- **Local developer workstation**: runs as part of `npx skills add` or a pre‑install hook, blocking or warning on risky skills.
- **CI/CD pipeline**: executed as a job in GitHub Actions/GitLab CI to audit skills before merging them into a repository or before publishing internal skill collections, leveraging SARIF outputs.[^9][^5]
- **Enterprise policy gateway**: integrated into internal skill registries or proxies that enforce corporate policies (e.g., block skills above a risk threshold).

***

## 5. Detailed Step‑by‑Step Implementation Plan

### Phase 0 – Foundation and Technology Choices

1. **Select primary implementation language and runtime**
   - Use **TypeScript/Node.js** for tight integration with the `skills` CLI and the wider JS tooling ecosystem.[^1]
   - Expose both a CLI wrapper and a programmatic API (library) to support different integration points.

2. **Define core data models**
   - `SkillSource`: description of where the skill comes from (git URL, shorthand, local path, ref).
   - `SkillManifest`: normalized view of `SKILL.md` metadata, instruction text, file tree, detected scripts, dependencies, external URLs.
   - `Finding`: `{ id, category, asixx, severity, file, line, message, risk, remediation }` with mappings to OWASP Agentic Top 10 IDs (ASI01–ASI10).[^7][^8]
   - `AuditResult`: aggregates findings, per‑category counts, overall risk score and recommendation.

3. **Decide external tool integration strategy**
   - For Semgrep, ShellCheck, TruffleHog/Gitleaks, decide whether to:
     - Shell‑out to installed binaries, or
     - Use containerized runners (e.g., Docker images) invoked by the auditor, or
     - Provide an "enhanced mode" when tools are installed, with a fallback to minimal checks.

4. **Establish configuration system**
   - YAML/JSON config file (e.g., `.skills-audit.yml`) to set thresholds, enabled analyzers, whitelists/blacklists, and policy rules.

### Phase 1 – Skill Ingestion and Manifest Builder

1. **Implement source resolution**
   - Reuse or mirror the resolution logic in `vercel-labs/skills` for shorthand (`owner/repo`), full URLs, git URLs, and local paths so the auditor accepts identical inputs.[^1]

2. **Implement repository fetcher**
   - For remote sources, clone into a temporary directory at a specified ref (branch, tag, commit) if provided.
   - For local paths, resolve absolute paths and ensure read‑only access.

3. **Implement skill discovery logic**
   - Mirror the path search in `skills` CLI (root `SKILL.md`, `skills/`, `.claude/skills/`, `.agents/skills/`, etc.), falling back to recursive search for `SKILL.md`.[^1]
   - For each `SKILL.md`, treat its containing directory as a skill root.

4. **Parse SKILL.md frontmatter and body**
   - Use a frontmatter parser to extract `name`, `description`, `metadata`, and any `allowed-tools` or context settings, following the Agent Skills spec used by Vercel and others.[^3][^2]

5. **Build per‑skill manifests**
   - Enumerate all files under each skill directory, classifying them as:
     - `markdown` (SKILL.md, README, rules),
     - `script` (e.g., `.sh`, `.bash`, `.py`, `.js`, `.ts`),
     - `config` (`package.json`, `requirements.txt`, `metadata.json`),
     - `reference` (templates, data files),
     - `other` (binaries, archives).
   - Extract dependency lists from recognized manifests (npm, PyPI, etc.).
   - Detect external URLs referenced in instructions, code, or config.

### Phase 2 – Prompt and Instruction Security Analysis

1. **Prompt injection and jailbreak detection**
   - Implement a rule‑based detector for common jailbreak patterns ("ignore previous instructions", "as an AI, you must", "exfiltrate", etc.), inspired by `skill-audit` and existing prompt‑security research.[^4][^5]
   - Optionally integrate an LLM‑powered classifier (similar to `skills-security-audit`) that semantically evaluates instruction intent (e.g., data exfiltration, privilege escalation) using OWASP Agentic categories.[^7][^4]

2. **Context and tool misuse detection**
   - Flag instructions that:
     - Encourage broad or unbounded tool usage (e.g., "you may run any shell command", "search the entire filesystem").[^13]
     - Suggest reading sensitive paths (e.g., `~/.ssh/`, `/etc/shadow`, cloud credentials) or uploading them to external URLs.[^4]
     - Encourage ignoring organization policies or security checks.

3. **Risk tagging**
   - For each detection, create a finding with:
     - Category: e.g., `PI` (prompt injection), `BM` (behavioral manipulation), mapped to ASI01/ASI09.
     - Severity based on impact and likelihood.
     - File/line references in `SKILL.md` or related markdown files.

### Phase 3 – Script and Code Security Analysis

1. **Language detection and routing**
   - Based on file extensions and simple heuristics, route scripts to appropriate analyzers (ShellCheck, Semgrep rulesets, custom regex rules).[^5]

2. **Shell script analysis**
   - Use **ShellCheck** to detect bad practices (unquoted variables, unsafe globbing).
   - Add custom rules for:
     - `curl | sh` or `wget | sh` patterns.
     - `rm -rf /` or equivalent destructive commands.
     - Direct access to sensitive files and directories (SSH keys, cloud credentials).

3. **Python and JavaScript/TypeScript analysis**
   - Use **Semgrep** rules for:
     - Insecure subprocess execution (e.g., `subprocess.Popen` or `child_process.exec` with unsanitized inputs).
     - Unsafe deserialization, eval, or dynamic import usage.
     - Insecure HTTP requests (lack of TLS verification, posting secrets).
   - Add rules tailored to agent skills (e.g., reading entire project root recursively, uploading arbitrary files).

4. **Secret scanning**
   - Use **TruffleHog** or **Gitleaks** to detect hard‑coded secrets (API keys, tokens, credentials).[^5]

5. **Generated findings**
   - Normalize all findings into the shared schema, with mappings to relevant Agentic Top 10 categories (e.g., ASI04 for malicious supply chain behaviors, ASI05 for unexpected code execution).[^8][^7]

### Phase 4 – Dependency and SBOM Analysis

1. **SBOM generation**
   - For each supported ecosystem, parse manifests:
     - Node: `package.json`, `package-lock.json`, `pnpm-lock.yaml`, etc.
     - Python: `requirements.txt`, `pyproject.toml`.
   - Generate an SBOM (CycloneDX or SPDX format) per skill bundle.

2. **Vulnerability lookup**
   - Query vulnerability databases (e.g., OSV, npm audit, PyPI advisories) for each SBOM component.
   - Record CVEs, severity (CVSS scores), and fixed versions.

3. **Policy evaluation**
   - Flag dependencies with critical or high‑severity vulnerabilities.
   - Optionally enforce policies like "no unpinned dependencies" or "no deprecated packages".

### Phase 5 – Trust and Provenance Evaluation

1. **Repository health checks**
   - Check whether the source repository:
     - Has a security policy file (`SECURITY.md`).
     - Uses recent commits and active maintenance.[^18]
     - Has any open security advisories or issues.

2. **Owner reputation and verification**
   - Optionally integrate with GitHub’s organization verification and popularity metrics (stars, forks) as weak trust signals.[^18]

3. **Signature checks (optional)**
   - If available, verify signed tags or releases to ensure integrity.

4. **Trust score contribution**
   - Combine provenance indicators into a secondary score that influences the overall risk rating but never overrides concrete vulnerability findings.

### Phase 6 – Policy Engine, Risk Scoring, and Reporting

1. **Define risk taxonomy and scoring model**
   - Adopt a numeric **Risk Score** (0.0–10.0) with bands (Safe, Risky, Dangerous, Malicious), similar to the `skills-security-audit` dashboard.[^4]
   - Map finding categories and severities to weighted contributions; for example, critical ASI05/ASI04 findings weigh more heavily than minor configuration warnings.[^8][^7]

2. **Policy configuration**
   - Allow organizations to configure:
     - Blocking thresholds (e.g., `block if score >= 6.0`).
     - Mandatory checks (e.g., fail if any hard‑coded secret is detected).
     - Ignores and exceptions (e.g., known benign patterns).

3. **Human‑readable report formats**
   - Produce per‑skill reports structured like:
     - Target, Risk Score and Level.
     - Critical / Warning / Info findings with IDs, file:line, risk explanation, and recommended action.[^4]
     - Summary counts and top risks per OWASP Agentic category.

4. **Machine‑readable outputs**
   - Emit JSON and **SARIF** (for GitHub Actions and other CI tools), as done by `skill-audit`.[^5]

### Phase 7 – Integration with Vercel Skills CLI

1. **CLI integration modes**
   - **Standalone auditor**: `npx skill-audit <source>` (or similar) to audit skills independently of installation.[^5]
   - **Pre‑install hook**: extend `npx skills add` with flags like `--audit` and `--audit-strict`:
     - `--audit`: run auditor, display report, prompt user to continue or abort.
     - `--audit-strict`: abort installation automatically if risk exceeds configured threshold.

2. **Internal integration**
   - Option 1: embed auditor as a dependency inside `vercel-labs/skills`.
   - Option 2: keep auditor as a separate CLI/library and have `skills` invoke it via a well‑defined API or subprocess.

3. **Skill discovery UX**
   - Enhance `npx skills find` and skills.sh UX by optionally displaying aggregated risk scores from precomputed audits for popular skills.[^12]

4. **Agent‑specific policies**
   - Support per‑agent policy overrides (e.g., stricter rules for agents with access to production infrastructure).

### Phase 8 – SDLC and Compliance Integration

1. **Requirements phase**
   - Define security requirements for using third‑party skills: mandatory auditing, allowed risk thresholds, and approved registries, aligning with OWASP secure development phases and ISO 27001 Annex A 8.25/8.26.[^19][^16][^9]

2. **Design phase**
   - Incorporate the auditor as a formal control in architecture diagrams and threat models, treating skills as a supply‑chain component (ASI04) protected by a dedicated gate.[^16][^7]

3. **Implementation phase**
   - Integrate the auditor into developer workflows (pre‑commit hooks, local CLI) so risky skills are flagged early, consistent with secure SDLC guidance that emphasizes early vulnerability detection.[^20][^21]

4. **Verification phase**
   - Run the auditor in CI/CD pipelines alongside SAST, DAST, and dependency scanning, and treat failing audits as build breakers for sensitive environments, in line with OWASP and ISO 27001 expectations for verification and testing.[^22][^16][^9]

5. **Operations and maintenance**
   - Periodically re‑audit installed skills as part of regular vulnerability management and monitoring, especially when new CVEs or Agentic Top 10 guidance emerge.[^14][^8]
   - Document audit results and exceptions to provide evidence for ISO 27001, SOC 2, or similar audits where secure development practices and supplier risk management are assessed.[^23][^9]

***

## 6. Compliance and Governance Mapping

### 6.1 OWASP Agentic Top 10

- **ASI01 – Agent Goal Hijack**: mitigated by prompt‑level analysis that flags manipulative or redirecting instructions in `SKILL.md` and supporting markdown.[^13][^7]
- **ASI02 – Tool Misuse and Exploitation**: mitigated by code and instruction analysis that detects unsafe tool usage patterns and guidance.[^7][^8]
- **ASI04 – Agentic Supply Chain Vulnerabilities**: directly addressed by repository provenance checks, SBOM and dependency scanning, and trust scoring.[^14][^8][^7]
- **ASI05 – Unexpected Code Execution**: mitigated by static analysis of scripts for dangerous commands and insecure execution flows.[^7][^5]
- **ASI06 – Memory and Context Poisoning**: mitigated by detecting hostile or deceptive long‑lived instructions in skills.[^13][^7]
- **ASI09 – Human–Agent Trust Exploitation** and **ASI10 – Rogue Agents**: partially addressed by highlighting behavioral manipulation patterns and misaligned goals embedded in skills.[^15][^7]

### 6.2 Secure SDLC / OWASP Guidance

OWASP’s secure development guidance emphasizes integrating security activities across requirements, design, implementation, and verification, plus supporting phases like metrics and training. By embedding skill auditing into each SDLC phase, the solution aligns with this guidance and supports maturity models like OWASP SAMM (governance, design, implementation, verification, operations).[^17][^24][^25][^16]

### 6.3 ISO 27001 and Related Standards

ISO 27001:2022 Annex A controls such as **8.25 Secure development lifecycle**, **8.26 Application security requirements**, **8.27 Secure system architecture and engineering principles**, and **8.28 Secure coding** expect organizations to integrate security into development and procurement of software, including third‑party components. The auditor provides:[^19][^9]

- Documented processes and tooling for assessing third‑party skills (supporting Annex A 8.25/8.26).[^9]
- Evidence that secure coding and dependency management practices are enforced for skill code (supporting 8.28).[^19][^9]
- Inputs to risk assessment and risk treatment records for components used by AI agents, aiding ISO 27001 audits and SOC 2 evidence collection.[^23][^9]

***

## 7. Roadmap and Iterative Delivery

### 7.1 Minimum Viable Auditor (MVP)

- Skill ingestion and manifest builder for `SKILL.md`, scripts, and manifests.
- Basic prompt injection heuristic rules.
- ShellCheck and Semgrep integration for shell and one programming language (e.g., JavaScript).
- Secret scanning via TruffleHog or Gitleaks.
- JSON report and CLI exit codes (pass/fail) suitable for CI.

### 7.2 Phase 2 Enhancements

- OWASP Agentic Top 10 mapping and structured risk scoring.
- SBOM generation and vulnerability lookups for npm/PyPI.
- Markdown/HTML human‑readable reports and batch reports similar to `skills-security-audit` examples.[^4]
- Optional LLM‑powered semantic analyzer for complex prompt and behavior patterns.

### 7.3 Phase 3 – Ecosystem Integration

- Tight integration into `vercel-labs/skills` as `skills audit` or `--audit` flag.[^1]
- Pre‑publish audits for curated skill collections (e.g., `vercel-labs/agent-skills`).[^26][^11]
- Skill risk surfacing in skills.sh and partner registries for discovery‑time transparency.[^12]

### 7.4 Phase 4 – Enterprise and Compliance Features

- Centralized policy management for organizations (e.g., risk thresholds, approved sources).
- Audit logging, dashboards, and evidence export aligned with ISO 27001 and SOC 2 assessments.[^23][^9]
- Periodic re‑auditing and notification system for newly discovered vulnerabilities in installed skills.

***

## 8. Conclusion

The Vercel skills ecosystem makes AI agent capabilities as easy to install as npm packages, but this convenience introduces a software‑supply‑chain attack surface that must be managed with the same rigor as traditional dependencies. By building a dedicated AI Agent Skill Security Auditing solution integrated into `npx skills` and the wider SDLC, organizations can systematically detect prompt‑level risks, code‑level vulnerabilities, and supply‑chain issues in skills before they reach production agents. Aligning the auditor with OWASP Agentic Top 10, OWASP secure SDLC guidance, OWASP SAMM, and ISO 27001 controls ensures that adopting agent skills remains compatible with modern security and compliance expectations.[^11][^12][^16][^9][^7][^1]

---

## References

1. [GitHub-OSS Fixit: Fixing Bugs at Scale in a Software Engineering Course](https://ieeexplore.ieee.org/document/9402190/) - Many studies have shown the benefits of introducing open-source projects into teaching Software Engi...

2. [Guides: Add Skills to Your Agent - AI SDK](https://ai-sdk.dev/cookbook/guides/agent-skills) - skills.sh to browse and discover community skills. Previous. Get started with Computer Use · Next. B...

3. [Agent Skills | Railway Docs](https://docs.railway.com/ai/agent-skills) - Private registries · Railpack · Deployments · Pre-deploy command · Start ... You can also install vi...

4. [skills-security-audit AI Agent Skill - Free Download - LLMBase](https://llmbase.ai/skills/agentnode-dev/skills-security-audit/) - Skill Security Audit. Overview. Scan and audit AI agent skills, plugins, and tool definitions for se...

5. [pors/skill-audit: Security auditing CLI for AI agent skills](https://github.com/pors/skill-audit) - Security auditing CLI for AI agent skills - detects prompt injection, secrets, and dangerous code pa...

6. [skill-security-auditor | Skills Mark...](https://lobehub.com/vi-VN/skills/eric861129-skills_all-in-one-skill-security-auditor) - Security auditor for AI Agent Skills. Analyzes skill files (SKILL.md, scripts, references) for vulne...

7. [Asi10: Rogue Agents](https://labs.lares.com/owasp-agentic-top-10/) - Agentic AI Applications go beyond simple question-and-answer interactions. They autonomously pursue ...

8. [OWASP Agentic Top 10 Released: AI Risks](https://astrix.security/learn/blog/the-owasp-agentic-top-10-just-dropped-heres-what-you-need-to-know/) - The new OWASP Agentic Top 10 outlines key AI agent risks like identity abuse and tool misuse. Astrix...

9. [ISO 27001:2022 Application Security Requirements](https://www.stackhawk.com/blog/iso-27001-application-security-compliance/) - Learn what the updated Annex A controls require and how to meet ISO 27001:2022 application security ...

10. [Vercel Launches Skills — “npm for AI Agents” with React Best Practices Built-in](https://www.reddit.com/r/codex/comments/1qfa7jm/vercel_launches_skills_npm_for_ai_agents_with/) - Vercel Launches Skills — “npm for AI Agents” with React Best Practices Built-in

11. [Quick Bites](https://www.theunwindai.com/p/vercel-releases-the-npm-of-agent-skills) - + Open Claude Cowork that connects with 500+ apps

12. [The Agent Skills Directory](https://skills.sh) - Skills are reusable capabilities for AI agents. Install them with a single command to enhance your a...

13. [Agent Skills - Claude API Docs](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview) - Agent Skills are modular capabilities that extend Claude's functionality. Each Skill packages instru...

14. [OWASP's Top 10 Agentic AI Risks Explained - HUMAN Security](https://www.humansecurity.com/learn/blog/owasp-top-10-agentic-applications/) - The new OWASP Top 10 for Agentic Applications highlights critical risks in autonomous AI systems. Le...

15. [The OWASP Agentic Top 10 2026: What It Means for AI Agents & NHIs](https://entro.security/blog/the-owasp-agentic-top-10-2026-what-it-means-for-ai-agents-and-non-human-identities/) - The "OWASP Top 10 for Agentic Applications 2026" highlighted one core reality: agents mostly amplify...

16. [Secure development and integration](https://devguide.owasp.org/en/02-foundations/02-secure-development/) - Referring to the OWASP Application Security Wayfinder development cycle there are four iterative pha...

17. [OWASP SDLC: Building your SSDLC with OWASP SAMM](https://codific.com/owasp-sdlc-owasp-samm/) - The traditional secure software development lifecycle consists of seven core phases: Planning and An...

18. [Vercel Labs](https://github.com/vercel-labs) - Develop. Preview. Ship. Creators of Next.js. Vercel Labs has 228 repositories available. Follow thei...

19. [ISO 27001 technological controls for software development](https://ictinstitute.nl/iso-27001-controls-software-development/) - The latest version of ISO 27001 contains multiple controls about secure development, engineering, co...

20. [Theory and practice in secure software development lifecycle: A comprehensive survey](https://wjarr.com/node/2929) - Software development security refers to the practice of integrating security measures and considerat...

21. [What Is a Secure Software Development Lifecycle (SDLC)?](https://www.oligo.security/academy/what-is-a-secure-software-development-lifecycle-sdlc) - 6 Stages of the Secure Software Development Lifecycle · 1. Requirements. During the requirements pha...

22. [ISO 27001 Secure SDLC: Key Requirements, Steps, and ...](https://www.konfirmity.com/blog/iso-27001-secure-sdlc) - This article explains ISO 27001 Secure SDLC in plain language. You'll learn what it means, why it ma...

23. [Build an ISO 27001 Secure Development Policy That Scales](https://sprinto.com/blog/iso-27001-secure-development-policy/) - ISO 27001 expects clear ownership over secure development tasks, ensuring security is operationalize...

24. [Comprehensive Guide to Implementing OWASP SAMM v2](https://securedebug.com/comprehensive-guide-to-implementing-owasp-samm-v2/) - It is structured around key business functions, which encompass governance, design, implementation, ...

25. [Leveraging the OWASP Software Assurance Maturity ...](https://www.nist.gov/document/cybersecurity-labeling-position-paper-owasp-samm) - SAMM is a comprehensive model built on five core business functions: Governance, Design,. Implementa...

26. [vercel-labs/slack-agent-skill](https://github.com/vercel-labs/slack-agent-skill) - An agent-agnostic skill for building and deploying Slack agents on Vercel. Supports two frameworks: ...

