# Corpus — managed / bytecode runtimes (JVM, .NET, Wasm, BEAM, Go)

Part of `runtime-core-vuln-hunt`. Memory bugs in the **native VM/JIT/GC/binding**
layer, not user bytecode logic. ✅ public exploit · ⚠️ confirmed/patched, no public
weaponized PoC · 🧪 fuzzer-crash/theoretical. **`[MEM]`** = true corruption ·
**`[GADGET]`** = CWE-502 deserialization logic.

## JVM / HotSpot
Richest native surface = **C2 (optimizing JIT)**: unsound optimization drops/
mis-places a safety check → OOB machine code.
| CVE/ID | Class |
|---|---|
| CVE-2024-21094 | `[MEM]` incorrect size validation → OOB array access (C2) |
| CVE-2024-21140 | `[MEM]` improper range-check elimination |
| CVE-2024-21210/-21235 | `[MEM]` faulty auto-vectorization → info-leak |
| CVE-2014-6504 | `[MEM]` incorrect range-check opt (bug 8022783) |
| JDK-8255763 (+backports) | `[MEM]` OSR miscompile, no CVE 🧪 |
- **`sun.misc.Unsafe`** = deliberate escape hatch (unchecked `putLong`/`copyMemory`);
  a deserialization/reflection primitive reaching an Unsafe write = arbitrary memory
  (being encapsulated, JEP 471+).
- **JNI** boundary: JVM doesn't bounds-check; most JVM native-corruption CVEs live
  in bundled native libs (image/crypto/zip), not HotSpot.
- **Java deserialization (ysoserial: CommonsCollections/Spring/Groovy)** = `[GADGET]`
  CWE-502, **not** memory corruption. Distinguish sharply.

## .NET / CoreCLR
| CVE | Class |
|---|---|
| CVE-2026-57108 | `[MEM]` type confusion (CWE-843) → DoS (.NET 8/9/10) |
| CVE-2007-0043 | `[MEM]` JIT → corruption (historical) |
| BinaryFormatter/NetDataContractSerializer | `[GADGET]` ysoserial.net; **removed by default .NET 9** |
Genuine `[MEM]`: **RyuJIT** (type confusion / bounds-check elision — mirrors
HotSpot C2), `Span<T>`/`stackalloc`/`Unsafe.As<T>` reinterpret casts, **P/Invoke**
marshalling size mismatches. Rare in CVE data (gadget path dominated history).

## WebAssembly runtimes
Canonical escape: **compiler/bounds-check mismatch** — check & access compute the
effective address two different ways → guest passes check, accesses elsewhere →
host R/W.
| CVE | Runtime | Class |
|---|---|---|
| CVE-2026-34971 | **wasmtime**/Cranelift aarch64 | `[MEM]` miscompile → **sandbox escape**, arbitrary host R/W (needs memory64 + Spectre/signal-traps off); 32.0.0→<36.0.7/<42.0.2/<43.0.1 ⚠️ |
| CVE-2025-64713 / OSV-2025-230 / CVE-2024-34250 | **WAMR** | `[MEM]` OOB during bytecode loading (`wasm_loader_*`) 🧪 |
| CVE-2025-58749 / -64704 | WAMR | `[INT]`/SIGSEGV → DoS ⚠️ |
| V8 **Liftoff** loop-register type confusion | V8-wasm | `[MEM]` ✅ (reportedly ITW; thin sourcing — caution) |
| CVE-2025-2135 (TurboFan) | V8-wasm | `[MEM]` map-inference → arbitrary R/W in V8 sandbox (V8CTF 0-day) ✅ |
Escape is almost always `[MEM]` compiler/loader, not deserialization. Discovery:
differential testing (WADIFF, RGFuzz) + JS↔Wasm boundary (Weaver).

## Erlang/BEAM & Go
- **BEAM ⚠️:** CVE-2026-55737 (`binary_to_term` ETF decode signed→unsigned **OOB
  write** → heap-ptr corruption), CVE-2026-75538 (`inet` TCP `{packet,4}` signed
  int overflow → heap overflow — **discovered by Claude**, triaged w/ Ada Logics),
  CVE-2026-59250 (`megaco` flex scanner buffer overflow). `binary_to_term` is the
  Erlang deserialize analogue but the bug is **true `[MEM]` in the C decoder**, not
  a gadget. Surface = `erts` + linked-in C **port drivers** + NIFs.
- **Go:** memory-safe by construction; realistic surface = `unsafe.Pointer`/`reflect`,
  **cgo** (JNI-class), data races on interface/slice headers (race detector), fast
  stdlib parsers (`encoding/*`,`archive/*` DoS). No notable runtime-core memory CVE.

## Open directions (🧪)
- JIT miscompiles (C2/RyuJIT/Cranelift) are the recurring `[MEM]` gold — differential
  fuzz optimized vs unoptimized output.
- WAMR/wasmtime loaders + bounds-check lowering per-arch (Cranelift aarch64 had one).
- BEAM NIF/port-driver C (binary_to_term variants, other `*_to_term`).

## Sources
openjdk JDK-8255763/8258842/8263870 · redhat CVE-2014-6504 · ubuntu USN-7096-1 ·
ysoserial · redhat/nvd CVE-2026-57108 · vuldb CVE-2007-0043 · nvd/tenable
CVE-2026-34971 · sentinelone CVE-2025-64713 · nvd CVE-2025-58749/2024-34250 ·
osv OSV-2025-230 · zellic V8CTF (CVE-2025-2135) · s2w V8 Liftoff · wiz
CVE-2026-55737/75538 · nvd CVE-2026-59250.
