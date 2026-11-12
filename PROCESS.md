# Project process and execution log

## Deliverable structure (updated to your data-only request)

- `README.md`: commands, dataset map, and entry point.
- `SOURCES.md`: source URLs, full citations, and their relationship to the data.
- `DATA_DICTIONARY.md`: schemas, denominators, and measurement caveats.
- `PROCESS.md`: this human-readable process record, including changes and execution decisions.
- `data/sample.csv`, `data/sample.provenance.json`, `data/ranking_top10000.csv`: frozen sample and selection provenance.
- `data/run/*.json`: raw, per-site observations, robots decisions, redirects, and failures.
- `data/exports/pages.csv`, `data/exports/sites.csv`, `data/exports/visits.csv`: analysis and visit audit tables.
- `netsec/`: sample preparation, collector, analysis, and validation code.
- `tests/`: offline regression tests for consequential measurement behavior.

## Requirements review — 2026-11-12

Read `project_scope.md`, `Network Security Proposal.md`, `feedback.md`, and the initial README. The professor prioritizes broader coverage and more pages over a second full collection, systematic page selection, staying within site boundaries, and complete citations. The proposed work is a measurement study, not an exploitation study.

## Design decisions

1. Select 150 domains from Tranco: 50 randomly selected without replacement in each of ranks 1–100, 101–1,000, and 1,001–10,000. Freeze the top 10,000 ranking frame, source archive SHA-256, and random seed 20261112. Equal allocation is deliberate; unweighted sample percentages are not estimates for the whole web.
2. Collect up to 40 successful, distinct, complete 2xx HTML pages per origin, including the homepage. Allow at most 80 page attempts, depth 5, and a 240-second per-site soft budget. Requests can overrun that soft budget by the active request/redirect/robots sequence. Use 12 site workers and at least 0.5 seconds between requests to a given hostname, with longer declared robots crawl delays honored.
3. Homepage canonicalization allows HTTPS redirects only between the sampled apex and its `www` alias. Then lock every followed page and redirect to the exact canonical HTTPS origin. Do not follow other subdomains, other domains, HTTP downgrades, nonstandard ports, or credential-bearing URLs.
4. Discover links recursively from HTML anchor elements. Prioritize less-visited first path segments, then less-visited discovery depths, then shallow depth and stable discovery order. Exclude query URLs, fragments, common assets, forms, and obvious account/state-changing paths. This balances sections and depth; it is not a uniform sample of all pages.
5. Check robots before requests; retain the decision and response text. Treat unavailable or ambiguous robots conservatively. Do not log in, submit forms, execute JavaScript, store cookies, or bypass challenges. Cap response bodies at 2 MB and exclude truncated pages from primary analysis. Validate TLS and reject DNS destinations with non-public addresses.
6. Store duplicate header fields as arrays. Separate enforced CSP, report-only CSP, and meta-delivered CSP. Analyze literal and nonce-normalized CSP differences separately. Report HSTS delivery differences without claiming that missing HSTS on one page disables previously stored browser HSTS.
7. Keep non-HTML pages, errors, denied robots, redirects out of scope, and suspected challenge pages in the audit but out of primary adoption/inconsistency denominators. Require a valid homepage and at least one valid interior page for within-origin comparison.

## Source verification and websites consulted

- Downloaded the public ranking archive from <https://tranco-list.eu/top-1m.csv.zip> and preserved the top-10,000 frame. The archive was downloaded on 2026-11-12; its underlying list date is not asserted unless separately verified.
- Read the Tranco project page: <https://tranco-list.eu/>.
- Located and read the prior paper: <https://www.dais.unive.it/~calzavara/papers/ndss21.pdf>.
- Checked the NDSS accepted-paper listing: <https://www.ndss-symposium.org/ndss2021/accepted-papers/>.
- Checked CSP semantics against <https://www.w3.org/TR/CSP3/> and HSTS against <https://www.rfc-editor.org/info/rfc6797/>.
- The paper PDF identifies NDSS 2021; a repository record has conflicting conference-year metadata, so the paper itself is used for the citation.

## Initial execution and correction

The first network command in the filesystem sandbox could not resolve external hosts. Network access was requested through the execution approval tool and granted for the ranking download and collection command. Python uses only the standard library; no package installation is needed.

The initial collection was a pilot. Inspecting early zero-page results showed that robots redirects were being conservatively rejected (for example, apple.com, microsoft.com, and wikipedia.org returned 301 for robots.txt). Updated robots handling to follow a bounded HTTPS apex/`www` redirect chain, while retaining its audit trail. This is separate from the strict page-origin rule. The pilot is preserved separately and excluded from the final analysis. It does not serve as the proposal's repeated-measurement experiment.

A compile check attempted to write Python bytecode to the macOS system cache and hit sandbox permissions. Subsequent checks use `python3 -B` or a workspace cache to avoid that side effect.

## User check-ins

The user requested this process log, a record of websites visited, and check-ins about structure. Proposed a conventional course-report structure and requested preferences through the asynchronous question tool while continuing independent implementation. Any required course template can replace the proposed structure.

## Scope update from the user

The user explicitly requested data and implementation only, with analysis and report writing reserved for the team. No final report or narrative interpretation will be created. The `data/exports/` directory contains machine-readable descriptive exports, not a written report. The user also confirmed that the sample must use a top list such as Radar or Tranco and include sources; the existing Tranco sample meets this requirement. The original ZIP is retained as `data/tranco-original.zip`.

## Verification in progress

Eleven offline regression tests passed for origin checks, apex/`www` homepage redirects, blocked cross-origin redirects, robots redirects and denial, HTML discovery, path diversity, nonce-only normalization, preservation of duplicate fields, HSTS screening, failed-site denominators, and final-URL deduplication. Final dataset validation will independently check site membership, origin confinement, page budgets, timestamps, and source hashes.

## Completed collection and post-collection review

The corrected collection completed all 150 sampled domains. It produced 2,287 page attempts and 1,803 originally eligible distinct HTML pages. An independent review identified standard-library robots matching limitations (wildcards, end anchors, and agent-group precedence). The supplied current collector now conservatively combines the original parser with the supplemental matcher before future requests and honors longer declared delays. The exact source used for the completed run remains in `data/run/collector_source.py`; its SHA-256 is recorded in metadata. No repeat collection was performed after this hardening.

Exports preserve `collector_eligible` and add `review_exclusions`. Supplemental robots decisions and final account-path review exclude 26 originally eligible rows, leaving 1,777 cleaned eligible pages. The primary data has 61 eligible homepages and 51 domains with an eligible homepage plus an eligible interior page. Thirty-five domains retain 40 cleaned eligible pages. These are coverage counts only; the team will interpret the results. Raw per-site JSON was not rewritten to conceal the original collection decisions. Descendants of reviewed pages may remain independently eligible; this sampling limitation is documented in the data dictionary.

The final integrity checks passed for all 150 result files, sample/ranking correspondence, duplicate final URLs, source archive hash, header field arrays, timestamps, page/depth/attempt caps, and origin confinement. Robots-pattern warnings remain visible in the validation output. Fourteen offline regression tests passed, including the supplemental matching and preservation of raw eligibility. An earlier regression fixture lacked a newly required count field; the fixture was corrected and the full suite passed.

## Stable ranking verification

Looked up Tranco's latest-list ID endpoint (<https://tranco-list.eu/top-1m-id>), which returned `PY2NJ`. Downloaded the permanent CSV from <https://tranco-list.eu/download/PY2NJ/1000000> and compared the entire file to the CSV decompressed from the original archive: the bytes match exactly. Added the stable list URL and CSV hash to `data/sample.provenance.json`. Preserved HTTP response headers. This verifies the list identity without relying on a changing latest URL.

## Final handoff request

The user accepted CSV and JSON and requested a ZIP as well. The handoff includes source code, raw data, cleaned descriptive exports, source citations, the process log, and a data dictionary. It includes no narrative project report or conclusions. The readable website inventory lists all 150 domains; detailed page/redirect/robots records are in the CSV audit, with the diagnostic pilot kept separately.
