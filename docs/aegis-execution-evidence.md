# AEGIS native execution — real evidence

_Captured on 2026-08-25 against a **local authorized lab** (a Python HTTP
server on 127.0.0.1:8000). No public/third-party system was scanned. Scope
file authorizes only 127.0.0.1; AEGIS_ENABLE_LIVE_SCANS=true._

Binaries present in this environment: nmap 7.94, nikto 2.5, wafw00f 2.x,
sqlmap 1.10.8, testssl.sh 3.x, whatweb (apt binary — broken Ruby env).

## Per-state / per-scanner results (actual JSON, trimmed)

### nmap (live=true)
```json
{
  "scanner": "nmap",
  "state": "live",
  "version": "Nmap version 7.94SVN ( https://nmap.org )",
  "finding_count": 1,
  "exit_code": 0,
  "error": null
}
```

### nikto (live=true)
```json
{
  "scanner": "nikto",
  "state": "live",
  "version": "-config+            Use this config file",
  "finding_count": 2,
  "exit_code": 0,
  "error": null
}
```

### wafw00f (live=true)
```json
{
  "scanner": "wafw00f",
  "state": "live",
  "version": "\u001b[1;97m______",
  "finding_count": 0,
  "exit_code": 0,
  "error": null
}
```

### sqlmap (live=true)
```json
{
  "scanner": "sqlmap",
  "state": "live",
  "version": "1.10.8#pip",
  "finding_count": 0,
  "exit_code": 0,
  "error": null
}
```

### whatweb (live=true)
```json
{
  "scanner": "whatweb",
  "state": "failed",
  "version": "<internal:/opt/rbenv/versions/3.3.6/lib/ruby/3.3.0/rubygems/core_ext/kernel_require.rb>:136:in `require': cannot load such file -- whatweb (LoadError)",
  "finding_count": 0,
  "exit_code": 1,
  "error": "parse failed: whatweb produced no fingerprint line"
}
```

### state matrix (same nmap adapter, different conditions)
```
condition      state        exit
live-disabled  disabled     0
--simulate     simulation   0
out-of-scope   (refused)    3
unauthorized   (refused)    4
```

---

## 2026-09-05 — ProjectDiscovery family + dalfox (native adapters)

_Captured against a **local authorized lab**: a Python `http.server` on
`127.0.0.1:8099` serving a small page with an `/admin/panel` link, plus a
deliberately broken server on `127.0.0.1:8098` that always answers 500. Scope
file authorizes `127.0.0.1` and `127.0.0.0/8` only; no public or third-party
system was contacted. `AEGIS_ENABLE_LIVE_SCANS=true`._

Engine versions: httpx (ProjectDiscovery) 1.x, katana 1.x, nuclei v3.11.1,
dalfox v2.13.0 — all built with `go install` and placed in `/opt/scanners`.

Run through Olympus, not by hand:
`olympus aegis run <scanner> --target http://127.0.0.1:8099 --kind url --scope scope.json --i-am-authorized`

| Scanner | State | Findings | Exit | Notes |
| --- | --- | --- | --- | --- |
| httpx | `live` | 4 | 0 | reachability + web server + 2 technologies |
| katana | `live` | 3 | 0 | 3 endpoints; `/admin/panel` elevated to MEDIUM |
| nuclei | `live` | 1 | 0 | one LOW match from a lab-local template |
| dalfox | `live` | 0 | 0 | clean target; `[{}]` correctly read as no findings |

```json
{"scanner": "httpx", "state": "live", "finding_count": 4, "exit_code": 0,
 "error": null, "real_execution": true}
{"scanner": "katana", "state": "live", "finding_count": 3, "exit_code": 0,
 "error": null, "real_execution": true}
{"scanner": "nuclei", "state": "live", "finding_count": 1, "exit_code": 0,
 "error": null, "real_execution": true}
{"scanner": "dalfox", "state": "live", "finding_count": 0, "exit_code": 0,
 "error": null, "real_execution": true}
```

### Three things the live runs taught us

**The sandbox is real.** The first attempt ran the binaries from `/root/go/bin`
and every scan returned `failed` with
`start_failed: [Errno 13] Permission denied`, `unprivileged_user: nobody`. The
sandbox had dropped privileges exactly as designed and `nobody` cannot read
`/root`. The binaries were moved to a world-readable `/opt/scanners`; the
refusal was correct behaviour, not a bug.

**nuclei cannot find its templates under the sandbox.** nuclei locates
`nuclei-templates` through `$HOME`, and the sandbox user's home is not the
operator's, so the engine exited 1 with "no templates provided for scan". The
adapter now takes `AEGIS_NUCLEI_TEMPLATES` and passes `-templates` explicitly.

**A bare host target is not a URL target.** `httpx --target 127.0.0.1` probes
80/443, which are closed on the lab host, and exits 2. Targeting
`http://127.0.0.1:8099` with `--kind url` returns `live` with 4 findings.
