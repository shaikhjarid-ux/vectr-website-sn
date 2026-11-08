# FMHY Safety Auditor

An open-source, free-tier website safety and hosted payload auditor. It fetches
a page through a guarded Cloudflare Worker proxy and analyzes it **statically**
in your browser: HTML parsing, JavaScript structure, redirects, disguised file
names and download links. It reports findings with evidence and says plainly
what it could not check.

> No detected findings does not establish that a website is safe. This scanner
> performs static analysis only; it cannot observe all runtime behavior or
> determine whether a downloaded file is malicious. An incomplete scan is shown
> as incomplete, not clean.

Status: Core under construction (see `docs/superpowers/`).

## Develop

    npm install
    npm test
    npm run lint
    npm run build     # writes dist/
    npm run dev       # build + wrangler dev

## Abuse and security reports

See `SECURITY.md`. Threat model: `docs/threat-model.md`.
