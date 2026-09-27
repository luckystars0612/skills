# REverie integration — mapping skill phases to the framework

REverie (`C:\Users\a\Desktop\REverie`) is the researcher's own agentic RE framework for
coordinated-disclosure vulnerability research. This skill uses REverie's domain model,
capability catalog, knowledge base, and reporting pipeline throughout. This reference maps
each skill phase to the concrete REverie types and capabilities to use.

---

## Domain model quick reference

| REverie type | This skill uses it for |
|---|---|
| `Package` | The analysis target — `Package::single(target)` for one binary, multi-component for bundles |
| `Component` + `ComponentRole` | Each binary: `KernelDriver`, `Service`, `Dll`, `Executable`, `DataOrConfig` |
| `Relation` + `RelationKind` | Cross-binary edges: `IoctlTo`, `IpcTo`, `TrustsInputFrom`, `Loads`, `Spawns`, `SharesStateWith` |
| `Hypothesis` + `BugClass` | Each vulnerability hypothesis — `OutOfBoundsRead/Write`, `UseAfterFree`, `IntegerOverflow`, `Toctou`, `UninitializedMemory`, `LogicFlaw`, `TypeConfusion`, `NovelPrimitive` |
| `InvestigationThread` | One line of inquiry per hypothesis, running in parallel, can branch |
| `Stage` | Labels: `Recon` → `Hypothesize` → `StaticProbe` → `DynamicProbe` → `Correlate` → `Repro` → `Report` → `Distill` (never gated — jump freely) |
| `Finding` + `ReproArtifact` | A confirmed, root-caused defect with evidence and reproduction |
| `Chain` + `ChainLink` | Cross-component impact composition (e.g., user-service IOCTL → kernel R/W) |
| `Evidence` + `Provenance` | Tool-produced observations with full attribution (capability, tool, timestamp) |
| `Session` | The whole investigation — spawns threads, records evidence, holds findings and chains |

---

## Phase → capability mapping

### Phase 0: Scope + intake → `Recon` stage

**Create the target:**
```rust
// Single binary
let target = Target::from_path("C:\\path\\to\\driver.sys");
let package = Package::single(target);

// Bundle: multiple binaries with relationships
let mut pkg = Package::named("VendorProduct");
let drv = pkg.add(Component::new(target_drv, KernelDriver));
let svc = pkg.add(Component::new(target_svc, Service));
pkg.component_mut(svc).relate(drv, RelationKind::IoctlTo);
pkg.component_mut(drv).relate(svc, RelationKind::TrustsInputFrom);
```

**REverie CLI triage:**
```sh
reverie sniff C:\path\to\driver.sys       # quick PE classify
reverie info C:\path\to\driver.sys        # SHA-256, sections, imports, packing
reverie info C:\path\to\driver.sys --store C:\research\store  # persist the session
```

**Capabilities used:**
- `recon.pe_sniff` — classify PE from headers (dep-free, instant).
- `recon.pe_info` — SHA-256, architecture, subsystem, sections with Shannon entropy,
  imports, `likely_packed` heuristic (entropy > 7.2). This is the automated first pass.
- `recovery.detect_packer` — if `recon.pe_info` says packed, identify the packer
  (UPX/ASPack/MPRESS/Petite/PECompact/FSG/Themida/VMProtect/Enigma).
- `recovery.unpack_strategy` → `recovery.unpack` — if packed, unpack before analysis.

**Knowledge base query:**
- `knowledge.search(query, k)` — BM25 retrieval: search for the vendor name, product,
  driver name, known CVE IDs. Prior `FindingRecord`s and `Technique`s from the same vendor
  are gold.
- `knowledge.suggest_leads_for(target)` — ranked leads from techniques matching the
  target's platform, vendor, and product. Feed these into Phase 2 as starting hypotheses.
- `knowledge.gaps` — unexplored `SurfaceNote`s in the target's `PlatformModel`. These are
  areas no prior session has checked — high-value for novelty.

### Phase 1: Attack surface mapping → `Recon` stage (continued)

**Capabilities used:**
- `static.imports` — list imported symbols and libraries. The primary screening tool.
- `static.list_functions` — enumerate functions for the dispatch table.
- `static.decompile` — decompile DriverEntry / initializer to find device creation,
  symlink, MajorFunction assignments.
- `static.xrefs_to` — find references to `IoCreateDevice`, `RpcServerRegisterIf`, etc.
- `static.strings` — find device names, pipe names, registry paths, format strings.

Direct idalib MCP tools are also available for finer-grained queries:
- `idb_open` — open the binary in IDA (do this once).
- `imports_query` — search imports by name pattern.
- `trace_data_flow` — trace data from a source to a sink.
- `callgraph` — function call graph.

### Phase 2: Pattern screening → `Hypothesize` stage

**Generate hypotheses:**
```rust
let h = Hypothesis::new(
    BugClass::OutOfBoundsWrite,
    "IOCTL 0x222004 METHOD_NEITHER handler @ 0x140001234",
    "memcpy(stack_buf, Type3InputBuffer, user_len) with no ProbeForRead \
     and no size cap — stack buffer overflow if user_len > 256",
);
let thread_id = session.spawn_thread(h, None);  // None = no parent thread
```

**Knowledge-seeded hypotheses:**
```rust
let generator = KnowledgeLeadGenerator::new(kb);
let thread_ids = orchestrator.seed(&mut session, &generator);
```
This auto-generates hypotheses from prior `Technique`s that match the target's platform
and vendor, ranked by confidence and relevance.

**Cross-binary hypotheses (bundles):**
```rust
let boundaries = crossbinary::trust_boundaries(&package);
let graph_gen = crossbinary::GraphLeadGenerator::new(&package);
let cross_threads = orchestrator.seed(&mut session, &graph_gen);
```
Seeds hypotheses from the package's `Relation` edges — e.g., "service A sends
user-controlled data to driver B via `IoctlTo` — does driver B validate?"

### Phase 3: Deep analysis → `StaticProbe` stage

**Capabilities used:**
- `static.decompile` — decompile the handler chain from boundary to sink.
- `static.xrefs_to` — cross-references to dangerous functions.
- `static.disassemble` — raw disassembly when decompiler output is ambiguous.
- idalib `trace_data_flow` — trace user-controlled data through function calls.

**Track evidence:**
```rust
let evidence = orchestrator.run_capability(
    &mut session, thread_id, "static.decompile",
    &json!({"address": "0x140001234"}).to_string(),
)?;
// Evidence is auto-attributed with Provenance (capability, tool, component, timestamp)
// and filed into the thread's evidence chain.
```

**Promote hypothesis:**
```rust
// Confirmed statically
session.threads[i].hypothesis.status = HypothesisStatus::Confirmed;

// Killed by a mitigating check
session.threads[j].hypothesis.status = HypothesisStatus::Refuted;
```

### Phase 4: Dynamic validation → `DynamicProbe` stage

**Lab harness (kernel drivers):**
```rust
// Upload and run a PoC on the lab VM in one call
let evidence = orchestrator.run_capability(
    &mut session, thread_id, "dynamic.run_poc",
    &json!({"artifact": "fuzz_harness.exe", "command": "{poc} --ioctl 0x222004"}).to_string(),
)?;
```

**Kernel debugging:**
- `dynamic.kd_breakpoint` — set breakpoint on the handler.
- `dynamic.kd_command` — run WinDbg commands (`!analyze -v`, `!poolused`, `dt`).
- `dynamic.kd_read_memory` / `dynamic.kd_write_memory` — inspect kernel state.
- `dynamic.kd_analyze` — auto-analyze a crash.

**Userland debugging (x64dbg):**
- `dynamic.set_breakpoint` — set breakpoint.
- `dynamic.step` — single-step.
- `dynamic.read_memory` / `dynamic.write_memory` — inspect state.
- `dynamic.registers` — register snapshot.

**Correlate kernel effect:**
```rust
// Link a userland trigger to a kernel crash/observation
let correlated = crossbinary::correlate_kernel_effect(trigger_evidence, kd_evidence);
session.record_evidence(correlated, thread_id);
```

### Phase 5: Severity + write-up → `Report` stage

**CVSS scoring (computed):**
```rust
let cvss = Cvss::from_vector("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
// cvss.base_score = 5.5, cvss.severity() = "Medium"
```

**Generate advisory:**
```rust
let evidence = orchestrator.run_capability(
    &mut session, thread_id, "report.write_advisory",
    &json!({
        "title": "Stack Buffer Overflow in IOCTL 0x222004",
        "class": "OutOfBoundsWrite",
        "root_cause": "memcpy with unchecked user-supplied length",
        "repro_kind": "IOCTL",
        "repro_description": "Send IOCTL 0x222004 with 4096-byte buffer",
        "affected_versions": ["1.0.0", "1.1.0"],
        "suggested_fix": "Cap InputBufferLength to sizeof(MY_STRUCT) before memcpy",
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
    }).to_string(),
)?;
// evidence.data contains the Markdown advisory — vendor-ready
```

Also write the finding into the VULN_REPORT template for the skill's own format
(`templates/VULN_REPORT.md`). The REverie advisory is the polished vendor-facing version;
the template is the researcher's internal record with more technical detail.

### Phase 6: Variant analysis → `Correlate` stage

**Cross-IOCTL variant scan:**
Use `static.decompile` on every IOCTL handler in the same driver. Same bug class in
another handler → new `Hypothesis` → new `InvestigationThread` (branched from the
original: `session.spawn_thread(h, Some(parent_thread_id))`).

**Cross-version diff:**
Open two versions of the binary, compare the vulnerable function. If the fix adds a check
that wasn't there → confirm the version range. If the "fix" is incomplete → new hypothesis.

**Patch bypass:**
If the binary has a known CVE fix, check whether the fix is complete. Hand off to
`cve-hunt` for deep patch-bypass analysis.

### Post-analysis: Distill → `Distill` stage

**Feed findings back into the knowledge base:**
```rust
let report = orchestrator.distill(&session, &mut kb, &GrowingDistiller);
// For each finding:
// 1. classify_novelty → PossiblyNovel / Variant / Known
// 2. mint_technique (if novel) → reusable technique with preconditions
// 3. mint_skill → check procedure for future sessions
// 4. record_finding → FindingRecord in the knowledge base
// 5. reinforce_from_session → bump confirmed counter on inspiring techniques
// 6. grow_platform_from_finding → mark surfaces as explored, add invariants
```

**Persist:**
```rust
engine.persist(&session);
// Saves session to <store>/sessions/<id>.json
// Saves knowledge base to <store>/knowledge.json
```

This is what makes the system improve over time: the next `reverie explore` on a similar
target gets better hypotheses from `knowledge.suggest_leads_for`, ranked by the confidence
earned from prior confirmed findings.

---

## REverie CLI cheatsheet for this skill

```sh
# Initial triage
reverie sniff driver.sys                            # quick classify
reverie info driver.sys                             # full PE facts
reverie info driver.sys --store C:\research\store   # persist session

# Full agentic loop (seeds hypotheses, explores, distills)
reverie explore driver.sys --store C:\research\store        # heuristic planner
reverie explore driver.sys --store C:\research\store --llm  # LLM planner

# Check assembled capability catalog
reverie capabilities

# Check tool provider status (IDA, WinDbg, x64dbg connectivity)
reverie providers

# Expose REverie as an MCP server for external agent hosts (e.g. Claude Code)
reverie serve driver.sys --store C:\research\store
```

**Environment variables for LLM planner:**
```sh
set REVERIE_LLM_MODEL=claude-sonnet-5
set REVERIE_LLM_API_KEY=sk-ant-...       # or use OAuth:
set REVERIE_LLM_OAUTH_TOKEN=...          # (from Claude Code session)
```

**Environment variables for lab VM:**
```sh
set REVERIE_LAB_HOST=192.168.1.100
set REVERIE_LAB_USER=researcher
set REVERIE_LAB_KEY=C:\Users\a\.ssh\id_rsa
set REVERIE_LAB_STAGING=C:\research\staging
```

---

## Capability ID reference (complete catalog)

### Recon (in-process, instant)
| ID | Input | Output |
|---|---|---|
| `recon.pe_sniff` | `{"path":"..."}` | `{is_pe, is_dll, is_driver_subsystem, machine, subsystem}` |
| `recon.pe_info` | `{"path":"..."}` | `{sha256, arch, subsystem, sections[{name,entropy}], imports, likely_packed}` |

### Recovery (in-process)
| ID | Input | Output |
|---|---|---|
| `recovery.detect_packer` | `{"path":"..."}` | `PackerVerdict` with signatures matched |
| `recovery.unpack_strategy` | `{"path":"...","packer":"..."}` | Recommended approach |
| `recovery.unpack` | `{"path":"...","backend":"..."}` | Unpacked binary path |
| `recovery.unpackers` | `{}` | Available backends |
| `recovery.dump_process` | `{"pid":N,"oep":"VA"}` | Dump path |
| `recovery.fix_iat` | `{"dump_path":"...","oep":"VA"}` | Repaired dump path |

### Research / Knowledge
| ID | Input | Output |
|---|---|---|
| `research.prior_art` | `{"query":"..."}` | Prior art results |
| `knowledge.suggest_leads` | (reads target from session) | `Vec<ScoredLead>` ranked by relevance |
| `knowledge.gaps` | (reads platform from session) | Unexplored `SurfaceNote`s |
| `knowledge.search` | `{"query":"...","k":6}` | `Vec<SearchHit>` (BM25) |

### Report
| ID | Input | Output |
|---|---|---|
| `report.write_advisory` | `{title, class, root_cause, repro_*, suggested_fix, cvss_vector, ...}` | Markdown advisory |

### Static (IDA Pro MCP)
| ID | Remote tool | Input |
|---|---|---|
| `static.list_functions` | `list_functions` | `{}` |
| `static.decompile` | `decompile_function` | `{"address":"0x..."}` |
| `static.disassemble` | `disassemble` | `{"address":"0x...","count":N}` |
| `static.xrefs_to` | `xrefs_to` | `{"address":"0x..."}` |
| `static.imports` | `list_imports` | `{}` |
| `static.strings` | `list_strings` | `{"filter":"..."}` |

### Dynamic user-mode (x64dbg MCP)
| ID | Remote tool |
|---|---|
| `dynamic.set_breakpoint` | `set_breakpoint` |
| `dynamic.remove_breakpoint` | `delete_breakpoint` |
| `dynamic.continue` | `run` |
| `dynamic.step` | `step_into` |
| `dynamic.read_memory` | `read_memory` |
| `dynamic.write_memory` | `write_memory` |
| `dynamic.registers` | `get_registers` |

### Dynamic kernel (WinDbg MCP)
| ID | Remote tool |
|---|---|
| `dynamic.kd_command` | `run_command` |
| `dynamic.kd_read_memory` | `read_memory` |
| `dynamic.kd_write_memory` | `write_memory` |
| `dynamic.kd_breakpoint` | `set_breakpoint` |
| `dynamic.kd_registers` | `get_registers` |
| `dynamic.kd_analyze` | `analyze` |

### Lab VM
| ID | Description |
|---|---|
| `dynamic.run_poc` | Upload + run PoC on lab VM, return output |
| `lab.exec` | Run a command on the lab VM |
| `lab.upload` | Upload a file to the lab VM |
| `lab.download` | Download a file from the lab VM |
