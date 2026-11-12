# Sources and data provenance

## Ranking used to select websites

**Tranco** is the ranking source for this dataset. No separate Radar download was used; Tranco itself aggregates multiple ranking providers.

- Permanent list: **PY2NJ**, <https://tranco-list.eu/list/PY2NJ>.
- Permanent CSV: <https://tranco-list.eu/download/PY2NJ/1000000>. Its complete contents were verified byte for byte against the CSV inside the original ZIP; the CSV hash is recorded in provenance.
- HTTP Last-Modified on the verified CSV: 2026-11-12 03:03:25 UTC; headers retained in `data/tranco-id-response-headers.txt`.
- Project: <https://tranco-list.eu/>
- Download endpoint: <https://tranco-list.eu/top-1m.csv.zip>
- Retrieved: 2026-11-12 UTC; exact sample-preparation timestamp in `data/sample.provenance.json`.
- Original archive: `data/tranco-original.zip`; its SHA-256 is in the provenance JSON.
- Frozen selection frame: `data/ranking_top10000.csv` (rank, domain; no header).
- Selected domains: `data/sample.csv` (rank, domain, stratum; header included).
- Seed: 20261112; selection algorithm in `netsec/prepare.py`.

The endpoint supplies a changing latest list. The exact archived bytes and frozen selection frame define this project's sample. Retrieval date is not asserted to be the ranking's underlying aggregation date. The sample is 50 domains per rank stratum (1–100, 101–1,000, 1,001–10,000), selected without replacement. It is not the top 150 domains, nor a uniform sample of the top 10,000.

**Ranking methodology citation:** Victor Le Pochat, Tom Van Goethem, Samaneh Tajalizadehkhoob, Maciej Korczyński, and Wouter Joosen. “Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation.” *Network and Distributed System Security Symposium (NDSS)*, 2019. <https://doi.org/10.14722/ndss.2019.23386>.

## Prior work named in the proposal

Stefano Calzavara, Tobias Urban, Dennis Tatang, Marius Steffens, and Ben Stock. “Reining in the Web's Inconsistencies with Site Policy.” *Network and Distributed System Security Symposium (NDSS)*, 2021. <https://doi.org/10.14722/ndss.2021.23091>. [Author-hosted paper](https://www.dais.unive.it/~calzavara/papers/ndss21.pdf).

This is the methodological reference from the proposal. The new dataset contains this project's observations, not data copied from that paper. Any comparison should account for differences in scale, origin coverage, browser execution, page sampling, and the definition of inconsistency. The exporter measures delivery differences, not the paper's policy-safety classifications.

## Header semantics

- W3C. *Content Security Policy Level 3*. Living Working Draft, accessed 2026-11-12. <https://www.w3.org/TR/CSP3/>. Supports separating enforced and report-only policies, retaining multiple policies, and treating per-response nonce rotation separately from other changes.
- Jeff Hodges, Collin Jackson, and Adam Barth. *HTTP Strict Transport Security (HSTS)*. RFC 6797, November 2012. <https://www.rfc-editor.org/rfc/rfc6797>. Supports the distinction between header delivery and stored host-wide browser state. Missing a header does not clear existing HSTS; a valid `max-age=0` has a different meaning.

## Primary measurement evidence

`data/run/DOMAIN.json` is the primary evidence for each sampled site. It records response headers, URLs, UTC timestamps, status codes, redirect chains, body hashes, robots evidence, exclusions, and collection limits. `data/exports/visits.csv` is an attempt/redirect/robots audit, not a guarantee that every listed attempt received a network response. `data/exports/sites.csv` lists all sampled domains including unsuccessful ones. `WEBSITES.md` is the readable inventory. `data/pilot_robots_redirect/` contains an earlier diagnostic run, excluded from final exports.
