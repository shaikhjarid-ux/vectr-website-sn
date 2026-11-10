// Stable error and coverage reason codes shared by the Worker, engine and UI.

export const ERROR_CODES = [
  'bad_request', 'blocked_target', 'bad_url', 'timeout',
  'too_many_redirects', 'upstream_error', 'rate_limited', 'budget_exhausted',
];

export const REASON_CODES = [
  // Fetch failures reuse the error codes as coverage reasons.
  ...ERROR_CODES,
  'response_truncated', 'fetch_timeout', 'script_parse_limit_reached',
  'resource_budget_exhausted', 'scan_deadline_reached', 'external_stylesheet_skipped',
  'unsupported_runtime_behavior',
  // Reasons named by later tasks in the plan:
  'script_parse_failed', 'script_analysis_timeout', 'blob_not_inspected',
  'binary_not_inspected', 'fetch_blocked_or_challenge', 'detector_failed',
];
