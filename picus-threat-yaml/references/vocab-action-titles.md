# Action title verbs

> Pulled from `GET /v1/threat-library/action-parameters` on the live platform, 2026-10-05.
> Picus **validates these on import** — a value outside the list is rejected. The endpoint
> accepts a `module_name` query parameter but ignores it: the response is byte-identical for
> all 12 modules, so one list serves every module.

Picus's own picker for the leading verb of an action `title`. The `title` itself is free text
(e.g. `Lateral Movement via PsExec`); this list is the vocabulary Picus's UI offers for the verb,
so starting a title with one of these keeps a custom threat consistent with the library.

Note `Exract` is Picus's own typo — reproduced here verbatim because that is the accepted value.

**52 verbs.**

```
Access  Add  Browse  Capture  Change  Check  Collect  Connect  Copy  Create  Decode  Decrypt  Delete  Disable  Discover  Download  Dump  Elevate  Enable  Encode  Encrypt  Escalate  Execute  Exfiltrate  Exploitation  Exract  Find  Gather  Generate  Get  Inject  Install  Kill  Modify  Move  Phishing  Query  Read  Register  Rename  Replace  Restart  Run  Save  Search  Send  Set  Start  Stop  Use  View  Write
```
