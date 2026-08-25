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
