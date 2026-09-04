# Custom Skills Collection

A curated collection of custom **Claude Code** skills for specialized, recurring
tasks. Each skill is a self-contained package of instructions, reference
material, and helper scripts that Claude can invoke on demand.

The repo is laid out as a drop-in skills library: clone it, point Claude Code at
it (or copy individual sub-directories into your own skills folder), and the
matching skill becomes available via the `Skill` tool or the `/<skill-name>`
 slash syntax.

---

## Repository Layout

```
.
├── README.md                       # You are here
└── <skill-name>/                   # One sub-directory per skill
    ├── SKILL.md                    # Required: skill frontmatter + instructions
    ├── scripts/                    # Optional: helper scripts / parsers
    ├── references/                 # Optional: detailed reference docs
    └── examples/                   # Optional: sample inputs / outputs
```

Every top-level sub-directory is a complete, installable unit. Move it, rename it,
    or ship just the pieces that match the task.

---

## Available Skills

### [picus-threat-yaml](picus-threat-yaml/) — Custom threats for Picus SCV

Author, validate, and package custom threat YAML files for the **Picus Security
Continuous Validation (SCV)** Threat Library.

**Triggers on**
- *"create a custom threat"*, *"write a threat.yaml"*, *"build a threat archive"*
- *"define attack campaigns"*, *"configure objectives / actions"*
- *"set MITRE ATT&CK tactics / techniques"*
- *"configure remote files or play_processes"*
- *"package a custom threat for Picus SCV"*
- Any Picus-specific question: modules, categories, UKC phases, result
  conditions, accepted field values
- Conversion from **Splunk SPL**, **Sigma rule**, or plain-text goal into an
  import-ready Picus campaign

**What it does**
- Guides the user through module selection (Endpoint, Network, Email, Web/Cloud,
  File-Download, etc.)
- Drafts `threat.yaml` with the correct schema, MITRE mappings, and result
  conditions
- Auto-detects whether the input is SPL / Sigma / plain-text and routes
  through the right parser
- Validates required fields, file-path consistency, and result-condition
  references
- Packages the threat as a ZIP archive ready for Picus SCV import

**Quick start**
```bash
# Show the skill instructions
cat picus-threat-yaml/SKILL.md

# Browse parser reference docs
ls picus-threat-yaml/references/parsers/
ls picus-threat-yaml/references/modules/

# Look at the example inputs
ls picus-threat-yaml/examples/
```

See [picus-threat-yaml/SKILL.md](picus-threat-yaml/SKILL.md) for the full
workflow.

---

### [cve-hunt](cve-hunt/) — Find new CVEs by attacking the boundary of an existing fix

Advisory-driven hunt for **new** vulnerabilities in a framework/library —
variants, incomplete fixes, and patch bypasses of an existing CVE — then prove
them **live in Docker** and package a submittable report. Distinct from a generic
code audit: it starts from a published fix (the guard reveals the primitive and
the boundary the maintainers assumed safe) and attacks where that assumption is
wrong. `disable-model-invocation: true` — invoke explicitly.

**Triggers on**
- *"find a new CVE / 0-day"*, *"bypass this patch"*, *"is this fix complete"*
- *"variant analysis"*, *"incomplete-fix / patch bypass"*
- *"reproduce and report a framework RCE / auth-bypass / SSTI"*

**What it does**
- Studies recent advisories + reads the actual fix code; confirms the current tip
- Generates falsifiable, boundary-focused hypotheses (guard gated on the wrong
  condition or tree-shaken out, sibling path unguarded, allowlist too narrow,
  normalization mismatch, secret-less hash ≠ auth, ineffective mitigation, SSTI)
- **Requires live Docker reproduction** before any finding is claimed; records the
  hypotheses that die
- Re-proves with the real mainstream library, locks the affected-version range
  (verified vs inferred), and packages: from-scratch `docker-compose`,
  dependency-free `exploit.py`, screen recording, self-contained zip, and an
  `ADVISORY.md` draft the human submits (never auto-posted upstream)

**Slash commands** (in [cve-hunt/commands/](cve-hunt/commands/))
- `/cve-hunt <target> [CVE/subsystem]` — the full hunt
- `/cve-matrix <poc-dir> <pkg> <versions…>` — build+exploit sweep → affected-range matrix
- `/cve-package <poc-dir>` — package a confirmed finding for submission

**Quick start**
```bash
cat cve-hunt/SKILL.md                 # the methodology
ls cve-hunt/templates/                # Dockerfile, docker-compose, exploit.py, version-sweep.sh, ADVISORY.md, ...
cp cve-hunt/commands/*.md ~/.claude/commands/   # enable the slash commands (skip README.md)
```

See [cve-hunt/SKILL.md](cve-hunt/SKILL.md) for the full workflow.

---

### [win-lpe-hunt](win-lpe-hunt/) — Hunt Windows LPE via binary analysis + hypothesis generation

Find **local privilege escalation** in Windows SYSTEM services, antivirus/EDR agents,
vendor updaters, profile/logon services, installers, and kernel drivers. Encodes the
confused-deputy bug class — *a privileged process does a file/registry op on a
user-influenceable path, and the user controls the namespace underneath it* — and turns a
target binary into many falsifiable hypotheses, each pairing a privileged op × a redirect
primitive × a race-win × a SYSTEM conversion.

**Triggers on**
- *"find LPE / privilege escalation in this binary"*, *"audit this SYSTEM service / AV / updater / driver"*
- *"give me new LPE ideas from this target"*, *"is this file op exploitable"*
- Any Windows binary that runs as SYSTEM/admin and touches user-controlled paths

**What it does**
- Opens the binary with the `idalib` IDA MCP and maps the surface: privileged file/registry
  ops, the **presence/absence of impersonation** around each (the fastest tell), attacker-input
  data-flow to path sinks, and weak-DACL named sections
- Emits **5–8+ ranked, falsifiable hypotheses** — each with an evidence line, a kill condition,
  the cheapest disproof, and a rank — then kills the cheap ones statically
- Confirms survivors dynamically with Procmon; prefers the deterministic **Cloud Filter
  (cfapi) FETCH_DATA race oracle** over oplocks
- Converts the primitive to SYSTEM, runs validation gates, and writes an impact-first report.
  Reproduced-or-it-didn't-happen; VERIFIED vs INFERRED on every claim; VM-only detonation

**Slash command** (in [win-lpe-hunt/commands/](win-lpe-hunt/commands/))
- `/win-lpe-hunt <binary | product | "survey my box"> [subsystem]` — the full hunt

**Quick start**
```bash
cat win-lpe-hunt/SKILL.md                 # the six-phase loop
cat win-lpe-hunt/references/PRIMITIVES.md # privileged ops, redirects, race-wins, conversions + idalib queries
cat win-lpe-hunt/references/HYPOTHESIS_TEMPLATE.md   # format + worked example + starter hypotheses
cp win-lpe-hunt/commands/*.md ~/.claude/commands/    # enable the slash command
```

See [win-lpe-hunt/SKILL.md](win-lpe-hunt/SKILL.md) for the full workflow.

---

## Adding a New Skill

1. Create a new sub-directory at the repo root named after the skill, in
   kebab-case (e.g. `my-new-skill/`).
2. Add a `SKILL.md` with YAML frontmatter:
   ```yaml
   ---
   name: my-new-skill
   description: >
     One-paragraph description. List concrete trigger phrases and the kinds
     of tasks the skill covers. Be specific — this drives auto-invocation.
   ---
   ```
3. Add `scripts/`, `references/`, `examples/` as needed. Keep each skill
   self-contained — no cross-references between skills.
4. Add a short entry to the **Available Skills** section above so the skill is
   discoverable from this README.

---

## Conventions

- **Naming** — kebab-case directory and `name:` field (e.g. `binja-scripting`).
- **Frontmatter** — `name` + `description` are required. `description` should
  list explicit trigger phrases so Claude knows when to invoke the skill
  automatically.
- **Independence** — each skill must work on its own. No skill depends on
  another skill's files being present.
- **Self-documentation** — the `SKILL.md` body should be enough for Claude to
  do the work; reference docs support but do not replace it.
- **Examples** — when a skill consumes a specific input format (rules,
  queries, configs), ship a small example in `examples/` so the workflow is
  obvious.

---

## License

Personal use. Add a license file before publishing externally.