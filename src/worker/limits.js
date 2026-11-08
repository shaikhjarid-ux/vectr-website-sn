// Request-size limits and abuse-control constants for /api/fetch.
export const REQUEST_LIMITS = Object.freeze({
  maxBodyBytes: 8192,
  maxUrlLength: 4096,
  cacheTtlSeconds: 600,
  retryAfterSeconds: 60,
});
