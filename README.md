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