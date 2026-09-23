# arc-test-component-e

Test component for ARC. Every branch is a deliberately-constructed scenario for
**CVE-2026-33814** ([GO-2026-4918](https://pkg.go.dev/vuln/GO-2026-4918)), which is
unusual in that it affects *two* packages at once:

| Affected package | Import path | Type | Fixed in |
|---|---|---|---|
| `golang.org/x/net` | `golang.org/x/net/http2` | non-stdlib | `v0.53.0` |
| `stdlib` | `net/http` | stdlib | Go `1.25.10` / `1.26.3` |

That makes it the right CVE for exercising `arc:positive:stdlib` and
`arc:positive:non-stdlib` independently, which is what each branch below does.

| Branch | Reaches | Expected labels | Expected remediation |
|---|---|---|---|
| `main` | neither | n/a — not scanned | n/a |
| `release-4.12` | `net/http` only | `arc:positive`, `arc:positive:stdlib` | none (Go Toolset owns the fix) |
| `release-4.13` | `golang.org/x/net/http2` only | `arc:positive`, `arc:positive:non-stdlib` | bump PR for `golang.org/x/net` |
| `release-4.14` | both | `arc:positive`, `arc:positive:stdlib`, `arc:positive:non-stdlib` | bump PR for `golang.org/x/net` only |
| `release-5.1` | both | same as `release-4.14` | **none** — 5.1 is a dev version, so ARC comments with manual-bump instructions instead |

`release-5.1` additionally requires `dev_versions: ['5.1']` on the `OCPBUGS`
project in arc-build-data, and a `'5.1'` entry in this component's mapping.
