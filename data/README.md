# data/

Source tables for the generated `src/worker/ranges.js` and `src/worker/special-domains.js`.

| File | Source registry | Capture |
|---|---|---|
| `iana-ipv4-special.csv` | IANA IPv4 Special-Purpose Address Registry | **NOT VERIFIED.** Transcribed by hand (model memory) on 2026-11-08 because the build sandbox could not reach iana.org. Contains one supplementary row (`224.0.0.0/4` multicast) from the IANA IPv4 address space registry. |
| `iana-ipv6-special.csv` | IANA IPv6 Special-Purpose Address Registry | **NOT VERIFIED.** Same as above. |
| `iana-special-use-domains.csv` | IANA Special-Use Domain Names registry | **NOT VERIFIED.** Same as above. The plan's global constraint cites a registry update of 2026-05-22; that date was not confirmed. |

The files use the registry's own column layout, so the real downloads can replace them unchanged:

    curl -o data/iana-ipv4-special.csv https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv
    curl -o data/iana-ipv6-special.csv https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv
    curl -o data/iana-special-use-domains.csv https://www.iana.org/assignments/special-use-domain-names/special-use-domains.csv
    node scripts/gen-ranges.mjs && npm test

After replacing them, record the capture date here and delete the "NOT VERIFIED" notes.
