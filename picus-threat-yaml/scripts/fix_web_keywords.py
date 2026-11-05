#!/usr/bin/env python3
"""Post-import fix for custom Web Application threats: set every action's keyword to ("page<display_id>").

Why this exists (verified on a live Picus deployment, 2026-10-19 — see references/web-keyword-fix.md):
  * `{PICUSID}` in a `.req` is replaced at replay time by the action's display_id. The display_id is
    assigned when the action is created (import), so it cannot be written into threat.yaml beforehand.
  * Picus stores keyword_queries verbatim — no macro substitution — and the public API (/v1) has no
    action-edit endpoint. The only edit path is the UI's internal API, which needs a browser session.
  * Re-importing creates NEW actions with NEW display_ids, so "fix the YAML and re-import" never converges.

Subcommands
  ids     list the actions of one or more custom threats (public API, GET only); optionally write a CSV
          and rewrite keyword_queries in the local threat.yaml(s) so the repo matches Picus.
  fix     set keyword = ("page<display_id>") on those actions through the UI API. Dry-run by default;
          --run writes. Stops at the first anomaly.
  verify  re-read every action and report keyword / description / Method / request state.

Auth
  public API : PICUS_URL + PICUS_REFRESH_TOKEN (or --refresh-token-file)  ->  POST /v1/auth/token
  UI API     : --cookie-file holding the browser Cookie header for the Picus host, e.g.
               "session_id=<uuid>; token=<jwt>"  (DevTools > Network > any /api/v2/ui/ request).
               The UI rotates the token while you use it: if you get 401, copy a fresh cookie and
               do not click around the UI while the script runs. Delete the file afterwards.

Known side effects of editing an action (any path, UI included) — the script compensates where it can:
  * description      : the UI edit form does not send it -> blanked.         Script resends it. KEPT
  * Method (title)   : server ignores `action_title`.                         Script also sends
                       `title` and `method`.                                  KEPT
  * needs_creds / is_remote : reset to null unless sent.                      Script resends. KEPT
  * Products (affected_products): cannot be set for category "Web Application"
                       (server: "affected_product should not be set if action category is not
                       Vulnerability...").                                     LOST — accept it.
  * is_sensitive_content: null -> false (same meaning).
  * Never send is_privileged / is_sensitive_content: the server rejects the whole request (400).

Examples
  export PICUS_URL=https://picus.example.local PICUS_REFRESH_TOKEN=...
  python3 fix_web_keywords.py ids    --threat 7903 --threat 7904 --csv ids.csv --yaml-dir "./Drupal ..."
  python3 fix_web_keywords.py fix    --threat 7903 --cookie-file cookie.txt --only 1000101        # dry-run
  python3 fix_web_keywords.py fix    --threat 7903 --cookie-file cookie.txt --only 1000101 --run  # one action
  python3 fix_web_keywords.py fix    --threat 7903 --threat 7904 --cookie-file cookie.txt --run   # the rest
  python3 fix_web_keywords.py verify --threat 7903 --threat 7904 --cookie-file cookie.txt
"""
import argparse
import csv
import json
import os
import re
import sys
import time
from pathlib import Path

try:
    import requests
    import urllib3
    import yaml
except ImportError:
    sys.exit("needs: pip install requests pyyaml")

urllib3.disable_warnings()

# fields allowed to differ after an edit; anything else changing stops the run
ACCEPTED_CHANGES = {"keyword", "keyword_queries", "updated_at", "affected_products", "is_sensitive_content"}


def target_keyword(display_id: int) -> str:
    return f'("page{display_id}")'


# ------------------------------------------------------------------ public API (GET only)
class PublicAPI:
    def __init__(self, base: str, refresh_token: str):
        self.base = base.rstrip("/")
        r = requests.post(f"{self.base}/v1/auth/token", json={"refresh_token": refresh_token},
                          verify=False, timeout=60)
        r.raise_for_status()
        self.h = {"Authorization": "Bearer " + r.json()["token"]}

    def get(self, path: str, **params):
        r = requests.get(self.base + path, params=params, headers=self.h, verify=False, timeout=120)
        r.raise_for_status()
        return r.json()

    def threat_actions(self, threat_id: int) -> tuple[dict, list[dict]]:
        t = self.get(f"/v1/threat-library/threats/{threat_id}")
        if t.get("is_predefined"):
            sys.exit(f"threat {threat_id} ({t.get('name')}) is a Picus predefined threat — refusing")
        mods = {m.get("name") for m in t.get("attack_modules") or []}
        if mods != {"Web Application"}:
            sys.exit(f"threat {threat_id} is {mods}, not Web Application")
        acts = [a for f in t.get("flows") or [] for a in f.get("actions") or [] if a.get("type") == "action"]
        return t, acts


def public_from_args(a) -> PublicAPI:
    base = a.url or os.environ.get("PICUS_URL")
    tok = os.environ.get("PICUS_REFRESH_TOKEN")
    if a.refresh_token_file:
        tok = Path(a.refresh_token_file).read_text().strip()
    if not base or not tok:
        sys.exit("set PICUS_URL and PICUS_REFRESH_TOKEN (or --url / --refresh-token-file)")
    return PublicAPI(base, tok)


def collect(api: PublicAPI, threat_ids: list[int]) -> list[dict]:
    rows = []
    for tid in threat_ids:
        t, acts = api.threat_actions(tid)
        for a in acts:
            rows.append({"threat_id": tid, "threat": t["name"], "action_id": a["display_id"],
                         "action_name": a["name"], "custom_keyword": target_keyword(a["display_id"])})
    names = [r["action_name"] for r in rows]
    dup = {n for n in names if names.count(n) > 1}
    if dup:
        print(f"WARNING: duplicate action names {sorted(dup)} — YAML matching by name is ambiguous")
    return rows


# ------------------------------------------------------------------ local threat.yaml
def yaml_actions(yaml_dirs: list[str]) -> dict:
    """name -> action dict from the local threat.yaml files (source for description / title)."""
    out = {}
    for d in yaml_dirs or []:
        doc = yaml.safe_load((Path(d) / "threat.yaml").read_text())["campaign"]
        for o in doc["objectives"]:
            for a in o["actions"]:
                out[a["name"]] = a
    return out


def rewrite_yaml_keywords(yaml_dir: str, name2id: dict) -> int:
    """Replace each action's keyword_queries item with ("page<id>"), keeping the file's formatting."""
    p = Path(yaml_dir) / "threat.yaml"
    lines = p.read_text().split("\n")
    out, cur, i, done = [], None, 0, 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"\s*- name: (.*)$", line)
        if m:
            cur = yaml.safe_load(m.group(1))
        out.append(line)
        if re.match(r"\s*keyword_queries:\s*$", line) and cur in name2id:
            ind = len(line) - len(line.lstrip())
            i += 1
            items = []
            while i < len(lines) and lines[i].strip().startswith("- ") and len(lines[i]) - len(lines[i].lstrip()) > ind:
                items.append(lines[i]); i += 1
            pad = items[0][: len(items[0]) - len(items[0].lstrip())] if items else " " * (ind + 4)
            out.append(f'{pad}- "(\\"page{name2id[cur]}\\")"')
            done += 1
            continue
        i += 1
    p.with_suffix(".yaml.bak").write_text("\n".join(lines))
    p.write_text("\n".join(out))
    return done


# ------------------------------------------------------------------ UI internal API (cookie session)
class UIAPI:
    def __init__(self, base: str, cookie_file: str):
        self.base = base.rstrip("/")
        self.s = requests.Session()
        self.s.verify = False
        c = Path(cookie_file).read_text().strip()
        if c.lower().startswith("cookie:"):
            c = c.split(":", 1)[1].strip()
        self.s.headers.update({"Cookie": c, "Accept": "application/json, text/plain, */*"})

    def detail(self, aid: int) -> dict:
        r = self.s.get(f"{self.base}/api/v2/ui/actions/action/{aid}/detail", timeout=60)
        if r.status_code == 401:
            sys.exit("UI API 401 — session expired/rotated: copy a fresh Cookie header into the cookie file")
        r.raise_for_status()
        return r.json()["data"]["action"]

    def edit(self, aid: int, payload: dict) -> requests.Response:
        return self.s.post(f"{self.base}/api/v2/ui/actions/action/{aid}", json=payload, timeout=60)


def edit_payload(a: dict, keyword: str, description: str, title: str) -> dict:
    """What the Threat Builder 'Edit action' form sends (buildActionPayload in the UI bundle), plus the
    fields the form drops. Do NOT add is_privileged / is_sensitive_content (400 for Web Application)."""
    p = {
        "name": a.get("name") or "",
        "attack_module": "Web Application",
        "category": "Web Application",
        "action_title": title, "title": title, "method": title,
        "affected_os": a.get("affected_os") or [],
        "ukc_phase_id": (a.get("ukc_phase") or {}).get("id"),
        "owasp_id": a.get("owasp_id"),
        "cve": a.get("cve") or None,
        "cwe": a.get("cwe") or None,
        "use_case": a.get("use_case") or None,
        "sources": a.get("sources") or None,
        "tags": a.get("tags") or None,
        "malware_family": a.get("malware_family") or None,
        "keyword": keyword,
        "affected_versions": a.get("affected_versions") or None,
        "user_definition": a.get("user_definition") or None,
        "execution_methods": a.get("execution_methods") or None,
        "country": a.get("country") or None,
        "data_type": a.get("data_type") or None,
        "wats_detail_id": a.get("wats_detail_id"),
        "description": description,
        "needs_creds": a.get("needs_creds") if a.get("needs_creds") is not None else False,
        "is_remote": a.get("is_remote") if a.get("is_remote") is not None else False,
    }
    return {k: v for k, v in p.items() if v is not None}


def _cmp(d: dict) -> dict:
    return {k: v for k, v in d.items() if k not in ACCEPTED_CHANGES}


# ------------------------------------------------------------------ commands
def cmd_ids(a):
    api = public_from_args(a)
    rows = collect(api, a.threat)
    for r in rows:
        print(f"{r['action_id']}\t{r['custom_keyword']}\t{r['threat']} :: {r['action_name']}")
    if a.csv:
        with open(a.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader(); w.writerows(rows)
        print(f"wrote {a.csv}")
    if a.yaml_dir:
        name2id = {r["action_name"]: r["action_id"] for r in rows}
        local = yaml_actions(a.yaml_dir)
        missing = sorted(set(local) - set(name2id))
        if missing:
            sys.exit(f"local actions not found on Picus (renamed or re-imported?): {missing[:5]}")
        for d in a.yaml_dir:
            print(f"{d}: {rewrite_yaml_keywords(d, name2id)} keyword_queries rewritten (backup threat.yaml.bak)")


def cmd_fix(a):
    api = public_from_args(a)
    rows = collect(api, a.threat)
    allowed = {r["action_id"]: r for r in rows}
    ids = sorted(allowed) if not a.only else a.only
    for i in ids:
        if i not in allowed:
            sys.exit(f"{i} is not an action of threats {a.threat} — refusing")
    ui = UIAPI(api.base, a.cookie_file)
    local = yaml_actions(a.yaml_dir)
    log = open(a.log, "a")
    for aid in ids:
        exp = allowed[aid]
        d = ui.detail(aid)
        if d.get("name") != exp["action_name"] or d.get("module") != "Web Application":
            sys.exit(f"{aid}: name/module mismatch ({d.get('name')!r}, {d.get('module')!r}) — stop")
        kw = exp["custom_keyword"]
        y = local.get(d["name"], {})
        desc = d.get("description") or y.get("description")
        title = d.get("action_title") or y.get("title")
        print(f"{aid} | {d.get('keyword')!r} -> {kw!r}")
        if d.get("keyword") == kw and d.get("description") and d.get("action_title"):
            print("   already correct, skip"); continue
        if not desc or not title:
            sys.exit(f"{aid}: description/Method already empty on Picus and not found in --yaml-dir — "
                     "pass the campaign dir so they can be restored; stop")
        p = edit_payload(d, kw, desc, title)
        if not a.run:
            print("   dry-run payload:", json.dumps(p, ensure_ascii=False)[:400]); continue
        r = ui.edit(aid, p)
        after = ui.detail(aid) if r.status_code < 300 else None
        log.write(json.dumps({"id": aid, "status": r.status_code, "resp": r.text[:300], "payload": p,
                              "before": d, "after": after}, ensure_ascii=False) + "\n"); log.flush()
        if r.status_code >= 300:
            sys.exit(f"{aid}: HTTP {r.status_code} {r.text[:300]} — stop (nothing changed on 4xx)")
        expect = dict(_cmp(d), description=desc, action_title=title,
                      needs_creds=p["needs_creds"], is_remote=p["is_remote"])
        diff = sorted(k for k in set(expect) | set(_cmp(after)) if expect.get(k) != _cmp(after).get(k))
        if after.get("keyword") != kw or diff:
            sys.exit(f"{aid}: verify failed keyword={after.get('keyword')!r} unexpected changes={diff} — stop")
        print("   ok")
        time.sleep(0.3)


def cmd_verify(a):
    api = public_from_args(a)
    rows = collect(api, a.threat)
    ui = UIAPI(api.base, a.cookie_file) if a.cookie_file else None
    bad = 0
    for r in rows:
        pub = api.get(f"/v1/threat-library/actions/{r['action_id']}")
        q = [k["query"] for k in pub.get("keyword_queries") or []]
        problems = [] if q == [r["custom_keyword"]] else [f"keyword={q}"]
        if not pub.get("description"):
            problems.append("description empty")
        if ui:
            d = ui.detail(r["action_id"])
            if not d.get("action_title"):
                problems.append("Method empty")
            if "{PICUSID}" not in (d.get("payload") or ""):
                problems.append("request lost {PICUSID}")
        if problems:
            bad += 1
            print(f"{r['action_id']} {r['action_name']}: {'; '.join(problems)}")
    print(f"{len(rows) - bad}/{len(rows)} actions OK")
    sys.exit(1 if bad else 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("ids", "fix", "verify"):
        s = sub.add_parser(name)
        s.add_argument("--threat", type=int, action="append", required=True,
                       help="custom threat id (internal id, e.g. 7903 — GET /v1/threat-library/threats?is_predefined=false)")
        s.add_argument("--url"); s.add_argument("--refresh-token-file")
        s.add_argument("--yaml-dir", action="append", help="local campaign dir(s) with threat.yaml")
        if name == "ids":
            s.add_argument("--csv")
        else:
            s.add_argument("--cookie-file", required=(name == "fix"))
        if name == "fix":
            s.add_argument("--only", type=int, action="append", help="restrict to these action ids")
            s.add_argument("--run", action="store_true", help="actually write (default: dry-run)")
            s.add_argument("--log", default="fix_web_keywords_log.jsonl")
    a = ap.parse_args()
    {"ids": cmd_ids, "fix": cmd_fix, "verify": cmd_verify}[a.cmd](a)


if __name__ == "__main__":
    main()
