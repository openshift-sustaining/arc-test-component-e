# arc-test-component-e

Test component for ARC. Every branch is a deliberately-constructed scenario for
**CVE-2026-46600** ([GO-2026-5942](https://pkg.go.dev/vuln/GO-2026-5942)), which is
unusual in that it affects *two* packages at once:

| Affected package | Import path | Type | Fixed in | Affected symbols used here |
|---|---|---|---|---|
| `stdlib` | `net` | stdlib | Go `1.26.6` / `1.27.0-rc.3` | `net.LookupCNAME` |
| `golang.org/x/net` | `golang.org/x/net/dns/dnsmessage` | non-stdlib | `v0.56.0` | `Message.Unpack`, `Parser.Answer` |

The two halves are genuinely independent code: `dns/dnsmessage` imports nothing but
`errors`, and the copy of it that `net` uses internally lives under the separate
`vendor/golang.org/x/net/dns/dnsmessage` import path. Reaching one half therefore
never drags the other in, which is what makes `arc:positive:stdlib` and
`arc:positive:non-stdlib` independently reachable.

> This is why the CVE is **not** one of the `net/http` + `golang.org/x/net/http2`
> pairs (e.g. CVE-2026-33814). `net/http` embeds `x/net/http2` as `h2_bundle.go`,
> and govulndb lists those bundled `http2*` symbols as the stdlib half — so
> reaching the `x/net` half makes the stdlib half RTA-reachable too, and a
> non-stdlib-only result is impossible.

| Branch | Reaches | Expected labels | Expected remediation |
|---|---|---|---|
| `main` | neither | n/a — not scanned | n/a |
| `release-4.12` | `net` only | `arc:positive`, `arc:positive:stdlib` | none (Go Toolset owns the fix) |
| `release-4.13` | `golang.org/x/net/dns/dnsmessage` only | `arc:positive`, `arc:positive:non-stdlib` | bump PR for `golang.org/x/net` |
| `release-4.14` | both | `arc:positive`, `arc:positive:stdlib`, `arc:positive:non-stdlib` | bump PR for `golang.org/x/net` only |
| `release-5.1` | both | same as `release-4.14` | **none** — 5.1 is a dev version, so ARC comments with manual-bump instructions instead |

## Go version

The stdlib half is only vulnerable for `1.26.0-0 <= go < 1.26.6`, so every branch
declares `go 1.26.0` in `go.mod` — that is what `cg` reads to decide whether the
stdlib half applies. The ARC scanner image ships Go `1.26.5` with
`GOTOOLCHAIN=local` (see the ARC `Dockerfile`), so it is inside the window and can
still build a `go 1.26.0` module.

`release-5.1` additionally requires `dev_versions: ['5.1']` on the `OCPBUGS`
project in arc-build-data, and a `'5.1'` entry in this component's mapping.
