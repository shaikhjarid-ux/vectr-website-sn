# [Vectr Website SN](https://vectr-website-sn.vectr-sn.workers.dev/)


An open-source, free-tier website safety and hosted payload auditor. It fetches
a page through a guarded Cloudflare Worker proxy and analyzes it **statically**
in your browser: HTML parsing, JavaScript structure, redirects, disguised file
names and download links. It reports findings with evidence and says plainly
what it could not check.

> No detected findings does not establish that a website is safe. This scanner
> performs static analysis only; it cannot observe all runtime behavior or
> determine whether a downloaded file is malicious. An incomplete scan is shown
> as incomplete, not clean.

Status: Core 0.1.0. See `docs/RELEASE_NOTES.md` for what is demonstrated, what was **not verified**, and the residual risks (including DNS rebinding). Detector documentation is in `docs/detectors/`; the staging checklist results are in `docs/staging-report.md`.

Rate limiting uses the Cloudflare Rate Limiting binding when it exists and otherwise a Cache API based limiter. Cache API entries are local to one data centre, so the fallback is a weaker, best-effort control.

## Develop

    npm install
    npm test
    npm run lint
    npm run build     # writes dist/
    npm run dev       # build + wrangler dev
    npm run test:e2e  # browser tests (needs: npx playwright install chromium)
    npm run staging   # staging checks (needs STAGING_URL and FIXTURES_URL)

## Abuse and security reports

See `SECURITY.md`. Threat model: `docs/threat-model.md`.
