# Web Application keywords — `("page<display_id>")` and the post-import fix

Verified on a live Picus deployment, 2026-10-19, with 5 custom web campaigns (94 actions) replayed
through Cloudflare into Splunk. This file supersedes any older text in this skill that calls
`{PICUSID}` "unpredictable" or recommends content-based keywords for web actions.

## How Picus attributes a web log to an action

1. Every `.req` path carries `{PICUSID}`. At replay the agent substitutes the **action's
   display_id** (the `actionId` column of the Picus CSV, `display_id` in the API). It is fixed
   for the life of the action — the same number in every run, not a per-session value.
   Checked on 13 predefined actions (keyword `("page221100")` ↔ action 221100, etc.) and on all
   94 custom actions (`/https/page1000112/index.php/...` in the Cloudflare log of action 1000112).
2. Picus pulls the SIEM records for the agent's IP in the campaign window and evaluates each
   action's `keyword_queries` as a case-insensitive substring match over the record's `_raw`.
3. So the right keyword is exactly what Picus writes for its own web actions:

   ```yaml
   keyword_queries:
       - ("page1000112")        # page + display_id, nothing else
   ```

   The prefix word is always `page`, even when the path says `/loginpage{PICUSID}.htm`.

## Why content-based keywords are wrong for web actions

Measured on run 257 (custom WordPress/PHP campaigns, Cloudflare Logpush → Splunk):

| Problem | Evidence |
|---|---|
| Cross-matching | Generic arms such as `("/wp-admin/admin-ajax.php")` (shared by 22 actions), `/wp-admin/admin.php`, `/wp-login.php`, `X-Requested-With` matched other actions' logs: 57/69 WordPress-plugin keywords and 4/9 PHP keywords hit a log line that belonged to a different action. "Logged" then proves nothing. |
| Body / header arms never match | Many WAF log feeds carry only the request line. This Cloudflare Logpush job ships 9 fields (ClientIP, ClientRequestHost, ClientRequestMethod, ClientRequestURI, Edge timestamps, EdgeResponseBytes/Status, RayID) — no headers, no body. An action whose keyword lives only in the body (`POST /` + `eael-resetpassword-submit`) can never be Logged, and since a campaign is Logged only when **every** action is, the whole campaign is stuck at Not Logged. |
| Fragile syntax | `"...poc\\"` (escaped quote) leaves a term unterminated; a literal `\r\n` in a keyword never occurs in a log. |
| Alert attribution | The same substring match runs over notables, so a generic keyword also produces false "Alerted". |

`("page<display_id>")` avoids all four: the token is unique per action and sits in the URI,
which every web log source records.

## The catch: the display_id does not exist until the action does

- `threat.yaml` has no field that references an existing action. Picus's own export
  (`GET /v1/threat-library/threats/{id}/export`) contains full action definitions, no action
  ids; `files/<n>.req` is named by the WATS file id, not the action id.
- Every import (`POST /v1/threat-library/threats/import`, or the UI import) **creates new
  actions**. Custom action ids come from one global, increasing counter (observed: 1000047 →
  1000085 → 1000099 → 1000101…1000194 in import order) and are never reused.
- Picus stores `keyword_queries` verbatim — no macro substitution, no auto-generated keyword for
  Web Application (the UI says "Port validation method is used… Optionally add your own keyword").
- The public API (`/v1`) has no action-edit endpoint; `PUT /v1/threat-library/threats/{id}` only
  changes threat metadata and objective → action_ids.

Therefore "fix the YAML and re-import" never converges (new import → new ids). The working flow
is **import once, then edit the keyword of each created action in place**.

## Workflow for every new custom web threat

1. Author `threat.yaml` normally. For `keyword_queries` write a placeholder that is still useful
   if the fix is skipped — a specific URI token of that request — but treat it as temporary.
   `validate_threat.py` warns on any web keyword that is not `("page<digits>")` as a reminder.
2. Import the archive.
3. Find the new threat's internal id: `GET /v1/threat-library/threats?is_predefined=false`.
4. List ids and sync the local repo:
   ```bash
   python3 scripts/fix_web_keywords.py ids --threat <id> --csv ids.csv --yaml-dir "<campaign dir>"
   ```
   (`--yaml-dir` rewrites `keyword_queries` in the local `threat.yaml` to `("page<id>")`, keeping
   a `.bak`; do NOT re-import that file — it is now a record of the live threat.)
5. Fix the keywords on Picus (needs a browser session, see below):
   ```bash
   python3 scripts/fix_web_keywords.py fix --threat <id> --cookie-file cookie.txt --yaml-dir "<dir>"            # dry-run
   python3 scripts/fix_web_keywords.py fix --threat <id> --cookie-file cookie.txt --yaml-dir "<dir>" --only <one action id> --run
   ```
   Open that one action in the UI (Threat Builder → Web Application → My Actions → Edit) and
   check Method, description, Custom Keyword. Then run without `--only`.
6. Verify, and keep the log (`fix_web_keywords_log.jsonl` holds before/after per action):
   ```bash
   python3 scripts/fix_web_keywords.py verify --threat <id> --cookie-file cookie.txt
   ```
7. Delete the cookie file and log out of the UI (the session token is a credential).

Editing by hand instead: Threat Builder → Web Application → **My Actions** → action → **Edit** →
**Detection Keyword** (collapsed; click to open) → **Custom Keyword** → `("page<id>")` → Save.
The action list has no id column — look actions up by name in the CSV from step 4. A hand edit
blanks the description and Method (below), so prefer the script.

## What editing an action does to its other fields

The edit endpoint is the UI's internal `POST /api/v2/ui/actions/action/{id}` (authenticated by the
browser cookie `session_id=…; token=…`; the public API token gets 401). Observed on 1000193/1000194:

| Field (UI label) | UI "Save" | `fix_web_keywords.py` |
|---|---|---|
| Custom Keyword | changed | changed |
| Request (`payload`, `wats_detail_id`), CVE, CWE, OS, UKC, OWASP, Use Case, Affected Versions, name | kept | kept |
| Description | **blanked** — the form does not send it | kept (resent; restored from `--yaml-dir` if already blank) |
| Method (`action_title`) | **blanked** — server ignores `action_title` | kept — also sent as `title` + `method` |
| `needs_creds`, `is_remote` | reset to null | kept (sent as false) |
| **Products** (`affected_products`) | **lost** | **lost** — no way to set it for category Web Application |
| `is_sensitive_content` | null → false | null → false (same meaning) |

Server rules learned the hard way (a rejected request changes nothing):
- `is_privileged` / `is_sensitive_content` in the body → 400 "should not be set if action
  category is not Attack Scenario".
- `affected_product` → 400 "should not be set if action category is not Vulnerability…";
  `affected_products` as a list → 400 (type error).

Products is display metadata only — request replay and keyword matching are unaffected — but tell
the user it will be empty after any keyword edit, and that the only way to keep it is to have the
right keyword at creation time, which the import cannot do.

**Always re-check after editing:** keyword `("page<id>")`, description present, Method present,
request still contains `{PICUSID}`. `verify` does this; spot-check one action in the UI too.

## Detection timing (not a keyword problem, but looks like one)

Cloudflare Logpush delivered run-257 logs to Splunk 7–16 minutes after the requests; Picus's last
detection query ran before the last batch was indexed, so 5 actions with correct keywords showed
Not Logged. Check `_indextime` vs Picus's search times (`index=_audit user=<picus user>`), then use
**Rerun detection** on the run (`POST /v1/simulations/{id}/run/{run}/rerun-detection`) instead of
editing keywords.

## Other `.req` pitfalls found in the same review

- Unresolved placeholders are sent literally (`/posts/$POSTID/…` reached the WAF as-is). Replace
  them with a concrete value.
- Prefixing the PICUSID segment with your own fixed marker (`/cfk001page{PICUSID}/…`, keyword
  `("cfk001page")`) would avoid the post-import edit, but it is **untested** — Picus's own
  packages only show alphabetic prefixes (`loginpage{PICUSID}`). Trial it on one small threat
  and confirm prevention and detection before relying on it.
