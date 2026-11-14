# data/

Source tables for the generated `src/worker/ranges.js` and `src/worker/special-domains.js`.

| File | Source registry | Capture |
|---|---|---|
| `iana-ipv4-special.csv` | IANA IPv4 Special-Purpose Address Registry | Official IANA download, captured 2026-11-12. |
| `iana-ipv6-special.csv` | IANA IPv6 Special-Purpose Address Registry | Official IANA download, captured 2026-11-12. |
| `iana-special-use-domains.csv` | IANA Special-Use Domain Names registry | Official IANA download, captured 2026-11-12. IANA's registry page showed "Last Updated 2026-05-22" when checked. |

The multicast range `224.0.0.0/4` is not a row in the IANA special-purpose registry, so `scripts/gen-ranges.mjs` adds it itself.

## Refreshing the tables

    curl -o data/iana-ipv4-special.csv https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv
    curl -o data/iana-ipv6-special.csv https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv
    curl -o data/iana-special-use-domains.csv https://www.iana.org/assignments/special-use-domain-names/special-use-domain.csv
    node scripts/gen-ranges.mjs && npm test

If the first line of a downloaded file starts with `<`, it is an error page rather than data. The generator will refuse it and say so.
