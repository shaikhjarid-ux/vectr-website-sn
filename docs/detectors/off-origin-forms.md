# off-origin-forms

Flags forms that submit to another site.

Findings are observations from static analysis. They are never verdicts, and "no findings" does not mean a site is clean.

## Rules

| Rule | Proposed severity | Triggers on |
|---|---|---|
| `form.off-origin-action` | low | a form whose action resolves to a different registrable domain |
| `form.password-off-origin` | medium | the same, when the form contains a password field |

Final severity is decided centrally: weak rules are capped at low when nothing else shares the target, and high needs corroboration by an independent detector or an auto-triggered path to a payload extension.

## Supported inputs

form elements with an http(s) action attribute, resolved against the effective base URL.

## Blind spots

Submissions performed by script (fetch, XMLHttpRequest, dynamically created forms) are not seen. The formaction attribute of buttons is only handled as a link reference.

## Confidence

Medium.

## False positives

Hosted payment and login providers, search boxes that post to a search engine, and newsletter services post off-site legitimately.
