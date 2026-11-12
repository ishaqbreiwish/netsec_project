# Dataset guide

These are data and implementation notes for the team's own analysis and report. There is no written research report in this repository.

## Authoritative inputs

| File | Meaning |
| --- | --- |
| `data/tranco-original.zip` | Original top-million Tranco download. |
| `data/sample.provenance.json` | Retrieval time, seed, sample design, archive SHA-256, and verified permanent list ID. |
| `data/ranking_top10000.csv` | Sampling frame: rank, domain; no header. |
| `data/sample.csv` | Selected 150 domains, ranks, and rank strata. |
| `data/run/metadata.json` | Run configuration, start/completion times, sample hash, Python version, collection-source snapshot hash. |
| `data/run/collector_source.py` | Exact collector source used for this run, before post-run hardening. Do not substitute the current source when describing how these observations were collected. |
| `data/run/DOMAIN.json` | Unmodified per-site raw observations and robots evidence. |

The selected sample has equal allocation across three rank strata; percentages over this sample are descriptive and unweighted. Failed domains are retained. Collection is performed from one machine/network location, with no location-specific representativeness claim.

## Exported tables (`data/exports/`)

### `pages.csv`: one row per page attempt

| Columns | Meaning |
| --- | --- |
| `rank`, `domain`, `stratum` | Tranco selection identity. |
| `requested_url`, `final_url` | Initial attempted page URL and final reached URL, or last decision target on failure. A denied URL may never have been sent. |
| `timestamp` | UTC, timezone-aware page record time; generally the final response request start, or attempt start if collection failed before that point. |
| `attempt` | One-based page-attempt index within a site. Redirects and robots requests are not additional page attempts. |
| `depth`, `parent_url` | Link-discovery depth and source page. Depth 0 is the homepage; depth is not URL path length. |
| `status`, `content_type` | Final response status and content type when available; blank on pre-response failures. |
| `is_homepage` | First attempted page for the domain. May resolve to a localized or canonical path. |
| `html`, `truncated`, `duplicate_final`, `challenge_suspected` | Eligibility diagnostics. HTML requires a declared HTML/XHTML MIME type. Challenge screening uses title heuristics, not reliable bot detection. |
| `collector_eligible` | Original raw collector eligibility. Requires complete, distinct, 2xx HTML with no recorded error or suspected challenge. |
| `review_exclusions` | JSON array of conservative post-collection exclusion reasons. |
| `eligible` | Cleaned export eligibility: collector eligibility AND no review exclusion. Use this for primary analysis. |
| `error` | Error or exclusion type, sometimes followed by diagnostic text. Empty does not imply eligibility. |
| `title`, `body_bytes`, `body_sha256` | Truncated page title, bytes read, and SHA-256 of retained body prefix. HTML bodies are not saved. |
| `csp_headers`, `csp_report_only_headers`, `hsts_headers` | JSON arrays preserving separate header fields in received order. `[]` means absent; `[""]` means an empty field was delivered. Never split these cells on commas. |
| `csp_present`, `csp_report_only_present`, `hsts_present` | At least one field delivered, regardless of policy validity or usefulness. |
| `*_normalized` | JSON arrays of conservative textual fingerprints, described below. |
| `meta_csp` | CSP meta-element content found in initial HTML; separate from header adoption. JavaScript-created elements are not observed. |
| `hsts_screen`, `hsts_max_age` | First-field screening labels: absent, positive_max_age, zero_max_age, invalid_or_ambiguous. Not a complete RFC grammar validator. |
| `redirect_chain` | JSON array of received redirect responses, destinations, and their security headers. |

### `sites.csv`: one row per sampled domain

Contains site identity, attempted and cleaned eligible page counts, raw collector eligible count, post-review exclusion count, homepage eligibility, canonical origin, depth and path-section coverage, runtime, and stop reason.

For each of `csp`, `csp_report_only`, `hsts`, it includes:

- `*_pages_present`: cleaned eligible pages with that field.
- `*_home_present`: field presence on an eligible homepage; blank if homepage is excluded.
- `*_presence_mismatch`: an eligible interior page differs from homepage in field presence.
- `*_raw_mismatch`: an eligible interior page's field array differs literally from homepage.
- `*_normalized_mismatch`: the same comparison after conservative textual normalization.
- `*_home_present_interior_absent` and `*_home_absent_interior_present`: direction of presence mismatch.
- `*_distinct_normalized_deliveries`: distinct fingerprints across cleaned eligible pages, including absence.

`comparable=True` requires an eligible homepage and at least one eligible interior page. Mismatch fields are blank for noncomparable domains. Do not treat those blanks as observed consistency.

### Other exports

| File | Meaning |
| --- | --- |
| `visits.csv` | Expanded page-attempt, page-redirect, and robots audit. A record is not proof of a successful fetch; check status and error. `timestamp_kind` identifies page record time or robots event time: exact per-hop request timestamps were not retained. |
| `difference_examples.csv` | First observed homepage/interior normalized difference per domain and header, retaining raw fields. These are examples of delivery variation, not demonstrated vulnerabilities. |
| `page_budget.csv` | Per-domain 1/5/10/20/40-page observations on the fixed cohort with 40 cleaned eligible pages. Order is actual eligible collection order. Page-budget 1 necessarily detects no interior difference. This is a paired prefix comparison, not separate random samples or a controlled BFS-vs-DFS experiment. |
| `summary.json` | Descriptive counts with explicit denominators, exclusions, statuses, and strata. No written interpretation. |
| `validation.json` | Independent integrity-check result and robots-pattern warnings. Passing integrity does not establish full standards compliance or prove absence of collection bias. |
| `robots_review.csv` | Originally eligible final pages flagged by the supplemental robots-pattern audit. Additional intermediate-redirect or final account-path exclusions appear in `pages.csv`. |
| `input_manifest.json` | SHA-256 for each raw JSON input used to generate the exports. |

CSV booleans are `True`/`False`; blank means unavailable/not applicable. Nested values are JSON encoded inside quoted CSV cells. With Python, use `csv.DictReader`, parse booleans explicitly (the string `False` is truthy), and `json.loads` for array cells.

## Normalization and interpretation boundaries

CSP raw comparison preserves all field values and their order. Normalized comparison collapses whitespace and replaces quoted nonce-source values with a placeholder. It preserves hashes, directive order, case, URLs, and reporting endpoints. It does not implement CSP semantic equivalence, source-list ordering equivalence, or policy-strength scoring. A normalized difference can reflect benign page customization or reporting differences; a literal difference can be nonce rotation alone. Neither proves XSS or another vulnerability. Report-only CSP is counted separately and is not an enforced policy.

HSTS normalization trims directive whitespace and lowercases directive names; it does not reorder directives or normalize values. All received fields are preserved; the screening helper looks only at the first field. Missing HSTS on a response does not clear a browser's cached host-wide HSTS state. Preload status, inherited HSTS, browser state, and exploitability were not measured. A zero-max-age label is not by itself a confirmed deactivation vulnerability.

The parser does not execute JavaScript, retain cookies, render pages, authenticate, or interact with forms. Body text is decoded as UTF-8 with replacement for discovery, which can miss non-UTF-8 links. It respects the ordinary standard-library robots parser during collection; the supplemental review catches common wildcard/end-anchor and agent-group-precedence issues afterward. That supplemental check is not a full RFC 9309 implementation. The current collector applies both checks before future requests, with conservative crawl-delay handling. No replacement pages were fetched after exclusions, and descendants discovered from an excluded page can remain in the data if independently eligible; this can affect the sampling path.

Only apex/`www` HTTPS canonicalization is allowed at bootstrap; then the exact origin is locked. Cross-subdomain and cross-domain redirects are excluded even when they may belong to the same organization. Robots redirects use a separate bounded apex/`www` rule. Candidate query links, common assets, and obvious account/state-changing paths are skipped; redirect destinations can contain queries. Final account-path review removes obvious account/login destinations from cleaned data. Redirect-only, failed, non-HTML, suspected challenge, and duplicate-final responses remain available for secondary analysis.

`time_budget` is a soft per-site cap checked between page attempts. A request, redirect sequence, robots lookup, DNS resolution, or declared crawl delay can exceed it. Do not infer all pages of a site were enumerated from `frontier_exhausted`; it refers only to this collector's bounded discovered frontier.

## Diagnostic data

`data/pilot_robots_redirect/` is an earlier diagnostic run before robots redirect handling was corrected. It is excluded from all primary exports and is not a controlled longitudinal repeat. `data/interim_validation/` preserves validation output made before collection and review were finished; it is superseded by `data/exports/validation.json`.
