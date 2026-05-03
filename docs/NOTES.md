# Architecture Notes — Phishing Domain Generator & Quishing Scanner

## Typosquat algorithm

The generator produces variants across 8 mutation categories. The order
of application matters for deduplication — the `seen` set prevents the
same string appearing under multiple technique names.

QWERTY adjacency data is hand-curated from a US keyboard layout. For
international keyboards (AZERTY, QWERTZ) the adjacent keys differ —
an extension point for future work.

## Homoglyphs: Unicode confusables

The Unicode Consortium maintains a full confusables.txt at
https://www.unicode.org/Public/security/revision-06/confusables.txt

This implementation uses a curated subset covering the most common Latin-
Cyrillic substitutions because those produce the most convincing IDN
homograph attacks. A production brand-protection tool would load the full
confusables database and generate all combinations.

## DNS registration check

`socket.getaddrinfo(domain, None)` resolves through the system resolver.
If the domain is registered and has A/AAAA records, it returns results.
NXDOMAIN raises `socket.gaierror`. This is not 100% reliable:
- Wildcard DNS on some TLD registries resolves all subdomains
- Parked domains without A records would show as "available" incorrectly

A more accurate check would use a WHOIS query or registry RDAP API, but
those are heavily rate-limited and require additional dependencies.

## Threading for bulk DNS checks

Each domain check is O(timeout) latency. Running 50 checks serially would
take up to 50 × 2s = 100 seconds. Using one thread per domain reduces
that to the maximum single timeout (2s). The thread count is capped by
Python's GIL for CPU-bound work but DNS resolution is I/O-bound, so
threading provides the expected speedup.

## Quishing

QR codes are decoded with `pyzbar` (wraps zbar — a C library with fast
barcode detection). `pyzbar` is an optional dependency. If it is not
installed, the tool reports that gracefully. The fallback attempts Pillow
but Pillow does not include a built-in QR reader, so a message is shown.

The generate path uses `qrcode` (pure Python) which is well-supported and
cross-platform.
