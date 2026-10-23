# Test fixtures

Real responses from the live sources, never hand-written.

| File | Source |
|---|---|
| `nvd-*.json` | NVD API 2.0 responses for the named CPE + version |
| `osv-*.json` | OSV.dev `/v1/query` responses for the named npm package + version |
| `epss-fixture-cves.json` | FIRST EPSS API response (2026-10-23) for the 15 CVEs that appear in the NVD/OSV fixtures. `CVE-2020-23064` is absent from it because EPSS publishes no score for it. |
| `kev-subset.json` | CISA KEV catalog 2026.10.21: the catalog header plus 4 entries copied verbatim (jQuery CVE-2020-11023 and HTTP/2 CVE-2023-44487, which match the fixtures, the newest entry and one with known ransomware use). The `count` field still states the full catalog size. |
| `wappalyzer/` | Upstream Wappalyzer entries (GPL-3.0, see its README) |
