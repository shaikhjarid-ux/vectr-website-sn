// Renders docs/staging-report.md from check results. Every check carries a
// status of "pass", "fail", "info" or "not verified"; nothing is recorded as
// passed unless it was actually observed.

export const CHECKS = [
  { id: 'redirect-private', title: 'Redirect to a private address is blocked', expect: '403 blocked_target' },
  { id: 'redirect-metadata', title: 'Redirect to the cloud metadata address is blocked', expect: '403 blocked_target' },
  { id: 'loop', title: 'Redirect loop is stopped', expect: '502 too_many_redirects' },
  { id: 'chain-6', title: 'Six redirect hops are refused', expect: '502 too_many_redirects' },
  { id: 'slow-drip', title: 'Slow-drip body hits the 8 s deadline', expect: '504 timeout' },
  { id: 'big-lying', title: 'Oversized body with a lying Content-Length is capped by bytes read', expect: '200 with truncated true and bytesRead 1048576' },
  { id: 'set-cookie', title: 'Set-Cookie is never returned or cached', expect: 'no set-cookie, second request is a cache miss' },
  { id: 'private-dns', title: 'Private DNS answer rejection (not a rebinding test)', expect: '403 blocked_target for a hostname that resolves to 10.0.0.1' },
  { id: 'rate-limit', title: 'Rate Limiting binding exists on this plan and limits requests', expect: 'some 429 responses within a burst, no 503' },
  { id: 'cache-locality', title: 'Cache behaviour across repeated requests', expect: 'recorded only (Cache API entries are local to one data centre)' },
  { id: 'subrequests', title: 'Subrequest count per scan', expect: 'recorded only (logged by the Worker; read with wrangler tail)' },
  { id: 'cpu', title: 'CPU time for a page at the 1 MiB cap', expect: 'within the Free plan CPU limit (read from the Cloudflare dashboard)' },
];

/**
 * @param {{id: string, status: 'pass'|'fail'|'info'|'not verified', observed?: string}[]} results
 * @param {{stagingUrl?: string, date: string}} meta
 */
export function renderStagingReport(results, meta) {
  const byId = new Map(results.map((r) => [r.id, r]));
  const lines = [
    '# Staging report',
    '',
    `Generated: ${meta.date}`,
    `Staging URL: ${meta.stagingUrl ?? 'not set'}`,
    '',
    'Status values: **pass** and **fail** were observed against the deployed staging Worker; **info** was recorded but is not a pass/fail check; **not verified** means the check was not run or could not be observed, and nothing should be assumed about it.',
    '',
    '| Check | Expected | Status | Observed |',
    '|---|---|---|---|',
  ];
  for (const c of CHECKS) {
    const r = byId.get(c.id) ?? { status: 'not verified', observed: 'not run' };
    lines.push(`| ${c.title} | ${c.expect} | ${r.status} | ${(r.observed ?? '').replace(/\|/g, '/')} |`);
  }
  lines.push('', 'DNS rebinding (answers that change between validation and connection) is not tested by any check above and remains a documented residual risk.', '');
  return lines.join('\n');
}
