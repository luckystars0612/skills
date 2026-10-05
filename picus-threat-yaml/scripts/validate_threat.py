#!/usr/bin/env python3
"""validate_threat.py — check a threat.yaml (or a built campaign dir / ZIP) against
the rules measured from the live Picus library on 2026-10-05.

Every check below corresponds to something observed in genuine Picus threats; the
vocabularies come from GET /v1/threat-library/action-parameters (see vocab.json).

Usage:
    python validate_threat.py <threat.yaml> [--files-dir <dir>]
    python validate_threat.py <campaign-dir>          # expects threat.yaml + files/
    python validate_threat.py <archive.zip>           # AES zip, password picus

Exit code 0 = no errors (warnings allowed), 1 = at least one error.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import zipfile
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

HERE = Path(__file__).resolve().parent
VOCAB = json.loads((HERE / "vocab.json").read_text())

# --- module facts, measured over 29 genuine Picus threats / 170 actions ------
MODULE_CATEGORIES = {
    "Endpoint Scenario": {"Attack Scenario", "Lateral Movement Techniques"},
    "Linux Endpoint Scenario": {"Attack Scenario"},
    "macOS Endpoint Scenario": {"Attack Scenario"},
    "Kubernetes Endpoint Scenario": {"Attack Scenario"},
    "Email": {"Malicious Code", "Vulnerability Exploitation"},
    "File Download": {"Malicious Code", "Vulnerability Exploitation"},
    "Web Application": {"Web Application"},
    "Data Exfiltration": {"Data Exfiltration"},
    "URL Filtering": {"URL Filtering"},
    "Azure Cloud Emulation": {"Azure ARM", "Azure Entra ID", "Azure m365"},
    "AWS Cloud Emulation": {"AWS"},
    "GCP Cloud Emulation": {"GCP"},
}
ENDPOINT_MODULES = {"Endpoint Scenario", "Linux Endpoint Scenario",
                    "macOS Endpoint Scenario", "Kubernetes Endpoint Scenario"}
# remote_files sits on the action for these, on each play_process for Endpoint
ACTION_LEVEL_FILES = {"File Download", "Email", "Data Exfiltration"}
# campaign/objective join operator Picus uses per module
JOIN = {"Endpoint Scenario": "and", "Linux Endpoint Scenario": "and",
        "macOS Endpoint Scenario": "and", "Kubernetes Endpoint Scenario": "or",
        "File Download": "or", "Email": "or", "Web Application": "or",
        "Data Exfiltration": "or", "URL Filtering": "or"}
# Where Picus omits `title`, measured over exported Picus threats:
#   Endpoint Scenario       0/218 (20 threats)
#   Linux Endpoint Scenario 4/104 (11 threats)  -> 4%, effectively omitted
#   macOS Endpoint Scenario 0/12
#   URL Filtering           0/2   (1 threat — thin)
# Where Picus always sets it: Kubernetes 174/174, Email 175/175,
# File Download 77/77, Data Exfiltration 174/174, Web Application 48/49.
# (An earlier count of 16/24 for Endpoint and 12/25 for Linux was contaminated by
# locally hand-authored threats, which supply every title.)
NO_TITLE = {"macOS Endpoint Scenario": "0/12",
            "Endpoint Scenario": "0/218",
            "Linux Endpoint Scenario": "4/104"}
AND_NOT_EXPECTED = ENDPOINT_MODULES | {"Data Exfiltration"}
AND_NOT_NEVER = {"File Download", "Email", "Web Application", "URL Filtering",
                 "AWS Cloud Emulation", "GCP Cloud Emulation"}

# tactic -> the ukc_phase Picus pairs it with, measured over 220 Picus actions.
# The two Picus-specific tactic names are NOT UKC phases: both `Stealth` (TA0005)
# and `Defense Impairment` (TA0112) pair with the phase `Defense Evasion`.
TACTIC_UKC = {
    "TA0001": "Initial Access", "TA0002": "Execution", "TA0003": "Persistence",
    "TA0004": "Privilege Escalation", "TA0005": "Defense Evasion",
    "TA0006": "Credential Access", "TA0007": "Discovery",
    "TA0008": "Lateral Movement", "TA0009": "Collection", "TA0010": "Exfiltration",
    "TA0011": "Command & Control", "TA0040": "Impact",
    "TA0042": "Resource Development", "TA0043": "Reconnaissance",
    "TA0112": "Defense Evasion",
}

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def err(self, where: str, msg: str) -> None:
        self.errors.append(f"{where}: {msg}")

    def warn(self, where: str, msg: str) -> None:
        self.warnings.append(f"{where}: {msg}")


def _op(rc) -> str | None:
    if not isinstance(rc, dict):
        return None
    return ((rc.get("condition") or {}).get("Operator"))


def _terms(rc) -> list:
    if not isinstance(rc, dict):
        return []
    return ((rc.get("condition") or {}).get("Terms") or [])


def _refs(rc) -> list[str]:
    out = []
    for t in _terms(rc):
        v = ((t.get("Left") or {}).get("Value"))
        if isinstance(v, str):
            out.append(v)
    return out


def check_archive_name(name: str, rep: Report, where: str) -> None:
    """files/<base64("<name>___<uuid><.ext>")> — one blob, padding kept."""
    base = name.split("/")[-1]
    if "___" in base:
        rep.err(where, f"payload name contains '___' before encoding — Picus stores ONE "
                       f"base64 blob of '<name>___<uuid>.<ext>', not "
                       f"'<base64>___<base64>.<ext>': {base[:48]}")
        return
    if "." in base:
        rep.err(where, f"payload name carries an extension outside the base64 blob "
                       f"(the extension belongs inside the encoded string): {base[:48]}")
        return
    try:
        dec = base64.b64decode(base + "=" * (-len(base) % 4)).decode("utf-8")
    except Exception:
        rep.warn(where, f"payload name is not base64 — Picus always encodes it: {base[:48]}")
        return
    if "___" not in dec:
        rep.warn(where, f"decoded payload name has no '___<uuid>' part: {dec[:60]}")
        return
    tail = dec.split("___", 1)[1]
    uid = tail.split(".", 1)[0]
    if not UUID_RE.match(uid):
        rep.warn(where, f"decoded payload name lacks a UUID after '___': {dec[:60]}")


def validate(doc: dict, files: set[str] | None, rep: Report) -> None:
    c = doc.get("campaign") or doc
    mod = c.get("module")
    where = "campaign"

    for req in ("name", "module", "objectives"):
        if not c.get(req):
            rep.err(where, f"missing required field `{req}`")
    if mod and mod not in MODULE_CATEGORIES:
        rep.err(where, f"unknown module {mod!r}; expected one of "
                       f"{sorted(MODULE_CATEGORIES)}")
    if c.get("severity") and c["severity"] not in ("High", "Medium", "Low"):
        rep.err(where, f"severity {c['severity']!r} must be High | Medium | Low")
    if c.get("threat_actor") and c["threat_actor"] not in VOCAB["threat_actors"]:
        rep.err(where, f"threat_actor {c['threat_actor']!r} is not a Picus-known actor "
                       f"(see references/vocab-threat-actors.md)")
    if isinstance(c.get("name"), str) and len(c["name"]) > 255:
        rep.err(where, "campaign name exceeds 255 chars")
    if isinstance(c.get("description"), str) and len(c["description"]) > 2000:
        rep.err(where, "campaign description exceeds 2000 chars")

    objs = c.get("objectives") or []
    crc = c.get("result_condition")
    if crc:
        if len(_terms(crc)) != len(objs):
            rep.err(where, f"campaign result_condition has {len(_terms(crc))} Terms but "
                           f"{len(objs)} objectives — equal in 20/20 real Picus threats")
        want = JOIN.get(mod)
        if want and _op(crc) and _op(crc) != want:
            rep.warn(where, f"campaign join operator is {_op(crc)!r}; Picus uses "
                            f"{want!r} for {mod}")
        for r in _refs(crc):
            m = re.match(r"^%objective-(\d+)%$", r)
            if not m:
                rep.err(where, f"campaign condition references {r!r}; expected %objective-N%")
            elif int(m.group(1)) > len(objs):
                rep.err(where, f"campaign references {r} but there are only {len(objs)} objectives")

    for oi, o in enumerate(objs, 1):
        ow = f"objective-{oi}"
        if o.get("type") and o["type"] not in VOCAB["objective_types"]:
            rep.warn(ow, f"type {o['type']!r} is outside the 16 values Picus uses "
                         f"(it is not free text)")
        acts = o.get("actions") or []
        if not acts:
            rep.err(ow, "has no actions — at least one is required")
        orc = o.get("result_condition")
        if orc:
            nt = len(_terms(orc))
            if nt > len(acts):
                rep.err(ow, f"result_condition has {nt} Terms but only {len(acts)} actions — "
                            f"a term would reference an action that does not exist")
            elif nt < len(acts):
                rep.warn(ow, f"result_condition covers {nt} of {len(acts)} actions; Picus "
                             f"usually lists them all (119/120 real objectives)")
            for r in _refs(orc):
                m = re.match(r"^%action-(\d+)%$", r)
                if not m:
                    rep.err(ow, f"condition references {r!r}; expected %action-N%")
                elif int(m.group(1)) > len(acts):
                    rep.err(ow, f"references {r} but there are only {len(acts)} actions")

        for ai, a in enumerate(acts, 1):
            aw = f"{ow}/action-{ai}"
            if not a.get("name"):
                rep.err(aw, "missing `name`")
            if "<unknown>" in json.dumps(a):
                rep.err(aw, "contains a '<unknown>' placeholder — this is an auto-generated "
                            "stub, not a usable action; map the goal to a real target or "
                            "hand-author it")
            cat = a.get("category")
            if mod in MODULE_CATEGORIES and cat and cat not in MODULE_CATEGORIES[mod]:
                rep.err(aw, f"category {cat!r} invalid for module {mod!r}; allowed: "
                            f"{sorted(MODULE_CATEGORIES[mod])}")
            if not a.get("ukc_phase"):
                rep.err(aw, "missing `ukc_phase` — set on 170/170 real Picus actions, "
                            "every module")
            elif a["ukc_phase"] not in VOCAB["ukc_phases"]:
                rep.err(aw, f"ukc_phase {a['ukc_phase']!r} not in the 18 valid phases")
            if mod in NO_TITLE and a.get("title"):
                rep.warn(aw, f"Picus rarely sets `title` for {mod} "
                             f"({NO_TITLE[mod]} of its actions do)")
            if mod not in NO_TITLE and not a.get("title"):
                rep.warn(aw, "no `title`; Picus sets one for this module "
                             "(100% of Email / File Download / Data Exfiltration actions)")

            # MITRE: Endpoint + Cloud only
            has_mitre = any(a.get(k) for k in ("tactic", "technique", "sub_technique"))
            if a.get("tactic") and a["tactic"] not in VOCAB["mitre_tactics"]:
                rep.err(aw, f"tactic {a['tactic']!r} is not a Picus tactic id; valid: "
                            f"{sorted(VOCAB['mitre_tactics'])}")
            if has_mitre and mod not in ENDPOINT_MODULES and "Cloud" not in str(mod):
                rep.warn(aw, f"tactic/technique set, but Picus never sets them for {mod} "
                             f"(0/92 such actions)")
            if a.get("sub_technique") and not a.get("technique"):
                rep.err(aw, "sub_technique set without technique")
            tac, ph = a.get("tactic"), a.get("ukc_phase")
            if tac in TACTIC_UKC and ph and ph != TACTIC_UKC[tac]:
                rep.warn(aw, f"tactic {tac} normally pairs with ukc_phase "
                             f"{TACTIC_UKC[tac]!r}, not {ph!r} (Picus deviates on a "
                             f"minority of actions, usually to 'Delivery')")

            # vocab-checked optional fields
            for fld, key, ref in (("owasp", "owasps", "accepted-values.md"),
                                  ("use_case", "use_cases", "accepted-values.md"),
                                  ("url_category", "url_categories", "accepted-values.md"),
                                  ("malware_family", "malware_families", "vocab-malware-families.md")):
                if a.get(fld) and a[fld] not in VOCAB[key]:
                    rep.err(aw, f"{fld} {a[fld]!r} is not an accepted value (see {ref})")
            for t in (a.get("tags") or []):
                if t not in VOCAB["tags"]:
                    rep.warn(aw, f"tag {t!r} is not in Picus's 258 known tags")
            for pl in (a.get("affected_platforms") or []):
                pair = [pl.get("name"), pl.get("architecture")]
                if pair not in VOCAB["platforms"]:
                    rep.err(aw, f"affected_platforms entry {pair} is not a Picus platform "
                                f"(see references/vocab-platforms.md)")

            # keyword_queries — plain strings in YAML
            kqs = a.get("keyword_queries")
            if not kqs:
                rep.err(aw, "missing `keyword_queries` — this is the entire detection half "
                            "of the action")
            else:
                for kq in kqs:
                    if isinstance(kq, dict):
                        rep.err(aw, "keyword_queries entry is a mapping; in YAML Picus uses "
                                    "plain strings (249/249). {id,query,type} is the API shape.")
                        continue
                    if not isinstance(kq, str):
                        rep.err(aw, f"keyword_queries entry is {type(kq).__name__}, expected str")
                        continue
                    has_not = "AND NOT" in kq
                    if has_not and mod in AND_NOT_NEVER:
                        rep.warn(aw, f"has an `AND NOT` filter, but Picus uses none for {mod} (0%)")
                    if not has_not and mod in AND_NOT_EXPECTED:
                        rep.warn(aw, f"no `AND NOT` noise filter; Picus adds one for {mod} "
                                     f"(78-100% of its actions)")

            # remote_files placement + payload naming
            arf = a.get("remote_files") or []
            prf = [(pi, rf) for pi, pr in enumerate(a.get("play_processes") or [], 1)
                   if isinstance(pr, dict) for rf in (pr.get("remote_files") or [])]
            if mod in ACTION_LEVEL_FILES:
                if prf:
                    rep.err(aw, f"remote_files nested in play_processes, but {mod} puts it at "
                                f"action level (41/41 real actions)")
                if not arf:
                    rep.err(aw, f"{mod} action has no `remote_files` — nothing would be delivered")
            if mod in ENDPOINT_MODULES and arf:
                rep.err(aw, f"remote_files at action level, but {mod} nests it inside each "
                            f"play_processes entry (0/78 real actions put it on the action)")
            for rf in arf + [r for _, r in prf]:
                fn = rf.get("file")
                if not fn:
                    rep.err(aw, "remote_files entry has no `file`")
                    continue
                if not fn.startswith("files/"):
                    rep.warn(aw, f"remote_files.file should start with 'files/': {fn}")
                check_archive_name(fn, rep, aw)
                if files is not None and fn not in files:
                    rep.err(aw, f"remote_files.file {fn!r} is not present in the archive")
                if mod in ("File Download", "Email") and not rf.get("is_downloaded"):
                    rep.err(aw, "File Download / Email remote_files needs `is_downloaded: true`")

            # Endpoint plumbing
            if mod in ENDPOINT_MODULES:
                pps = a.get("play_processes") or []
                if not pps:
                    rep.err(aw, "Endpoint action has no `play_processes`")
                for pi, pr in enumerate(pps, 1):
                    if not isinstance(pr, dict):
                        rep.err(aw, f"play_processes[{pi}] is not a mapping")
                        continue
                    if not (pr.get("path") or pr.get("arguments")):
                        rep.err(aw, f"play_processes[{pi}] needs a `path` or `arguments`")
                    # A dropper that is delivered but never executed makes the
                    # hashes in keyword_queries unreachable, so detection can never
                    # fire. Picus always runs the dropped file (cf. PUMAKIT).
                    for rf in (pr.get("remote_files") or []):
                        dp = rf.get("path") or ""
                        blob = f"{pr.get('path','')} {pr.get('arguments','')}".lower()
                        # Compare on the basename, case-insensitively: Windows paths
                        # are case-insensitive and Picus's own casing is inconsistent
                        # (BlackMatter drops `ChaCha20_enc.exe`, runs `Chacha20_enc.exe`).
                        leaf = re.split(r"[\\/]", dp)[-1].lower()
                        if leaf and leaf not in blob:
                            # Legitimate pattern: a payload delivered and *registered*
                            # for later loading rather than executed here — e.g. an SSP
                            # DLL dropped into System32 then added to Security Packages
                            # via reg.exe, loaded by LSASS at next boot. Hence a warning.
                            rep.warn(aw, f"play_processes[{pi}] delivers {dp!r} but neither "
                                         f"`path` nor `arguments` references it. Fine if the "
                                         f"payload is registered for later loading; otherwise "
                                         f"it is never executed and its hashes can never "
                                         f"appear in telemetry")
                    for sc in (pr.get("success_conditions") or []):
                        if not isinstance(sc, dict):
                            rep.err(aw, f"play_processes[{pi}].success_conditions entry is "
                                        f"{type(sc).__name__}, expected a mapping")
                        elif not sc:
                            # Picus itself emits an empty entry (2 cases in
                            # BlackMatter Ransomware Campaign) — unusual, not invalid.
                            rep.warn(aw, f"play_processes[{pi}].success_conditions has an empty "
                                         f"entry; the process will have no success check")
                        elif isinstance(sc.get("output"), str) and not sc["output"].strip():
                            rep.err(aw, f"play_processes[{pi}].success_conditions `output` is "
                                        f"blank — the check would pass unconditionally")
                        elif "output" not in sc and "code" not in sc:
                            rep.err(aw, f"play_processes[{pi}].success_conditions entry needs "
                                        f"`output` (preferred) or `code`, got {sorted(sc)}")
                if a.get("success_conditions"):
                    rep.err(aw, "success_conditions at action level — Picus puts it on the "
                                "play_process (68/68 real cases)")
                arc = a.get("result_condition")
                if arc:
                    npr = len(a.get("play_processes") or [])
                    nt = len(_terms(arc))
                    if nt > npr:
                        rep.err(aw, f"result_condition has {nt} Terms but only {npr} processes")
                    elif nt < npr:
                        rep.warn(aw, f"result_condition covers {nt} of {npr} processes; Picus "
                                     f"usually lists them all (61/64 real actions)")
                    for r in _refs(arc):
                        m = re.match(r"^%process-(\d+)%$", r)
                        if not m:
                            rep.err(aw, f"action condition references {r!r}; expected %process-N%")
                        elif int(m.group(1)) > len(a.get("play_processes") or []):
                            rep.err(aw, f"references {r} but there are only "
                                        f"{len(a.get('play_processes') or [])} processes")
            else:
                if a.get("play_processes"):
                    rep.err(aw, f"play_processes set, but {mod} is not an Endpoint module")

            # module-specific required payload
            if mod == "Web Application" and not a.get("request_content"):
                rep.err(aw, "Web Application action needs `request_content` pointing at a .req file")
            if mod == "URL Filtering":
                if not a.get("filter_url"):
                    rep.err(aw, "URL Filtering action needs `filter_url`")
                if not a.get("url_category"):
                    rep.err(aw, "URL Filtering action needs `url_category`")
            if mod == "Data Exfiltration":
                for f in ("country", "data_type"):
                    if not a.get(f):
                        rep.warn(aw, f"Data Exfiltration action usually sets `{f}`")


def load(target: Path) -> tuple[dict, set[str] | None]:
    if target.is_dir():
        y = target / "threat.yaml"
        if not y.exists():
            sys.exit(f"no threat.yaml in {target}")
        files = {f"files/{p.name}" for p in (target / "files").glob("*")} \
            if (target / "files").is_dir() else set()
        return yaml.safe_load(y.read_text()), files
    if target.suffix.lower() == ".zip":
        # Picus archives are AES-256, which Python's zipfile cannot decrypt, so
        # extract with 7z. Fall back to zipfile for a plain/ZipCrypto archive.
        import shutil
        import subprocess
        import tempfile
        if shutil.which("7z"):
            with tempfile.TemporaryDirectory() as td:
                r = subprocess.run(["7z", "x", "-ppicus", f"-o{td}", str(target), "-y"],
                                   capture_output=True, text=True)
                if r.returncode != 0:
                    sys.exit(f"7z could not extract {target} (password 'picus'):\n{r.stdout[-500:]}")
                y = next(Path(td).rglob("threat.yaml"), None)
                if y is None:
                    sys.exit("no threat.yaml inside the archive")
                root = y.parent
                files = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()
                         and p != y}
                return yaml.safe_load(y.read_text()), files
        try:
            with zipfile.ZipFile(target) as z:
                names = z.namelist()
                inner = next((n for n in names if n.endswith("threat.yaml")), None)
                if not inner:
                    sys.exit("no threat.yaml inside the archive")
                prefix = inner[: -len("threat.yaml")]
                doc = yaml.safe_load(z.read(inner, pwd=b"picus").decode())
                files = {n[len(prefix):] for n in names if n != inner and not n.endswith("/")}
                return doc, files
        except RuntimeError as e:
            sys.exit(f"cannot read archive — install 7z to check AES archives: {e}")
    return yaml.safe_load(target.read_text()), None


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", type=Path, help="threat.yaml, campaign dir, or .zip")
    ap.add_argument("--files-dir", type=Path, help="override the files/ directory to check against")
    args = ap.parse_args()

    doc, files = load(args.target)
    if args.files_dir:
        files = {f"files/{p.name}" for p in args.files_dir.glob("*")}

    rep = Report()
    validate(doc, files, rep)

    for e in rep.errors:
        print(f"ERROR   {e}")
    for w in rep.warnings:
        print(f"WARN    {w}")
    c = doc.get("campaign") or doc
    nacts = sum(len(o.get("actions") or []) for o in (c.get("objectives") or []))
    print(f"\n{c.get('module')} | {len(c.get('objectives') or [])} objectives | {nacts} actions")
    print(f"{len(rep.errors)} error(s), {len(rep.warnings)} warning(s)")
    sys.exit(1 if rep.errors else 0)


if __name__ == "__main__":
    main()
