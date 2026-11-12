# Security-header consistency measurement data

Implemented and executed for the project proposal and professor's feedback. This repository provides data and reproducible tools; your team will analyze the observations and write the report.

**Completed:** 150 domains from [Tranco list PY2NJ](https://tranco-list.eu/list/PY2NJ), up to 40 eligible pages per origin, 2,287 page attempts, and 1,777 cleaned eligible pages. Fifty-one domains support homepage/interior comparisons. Unreachable, blocked, and excluded domains remain in the dataset.

Start with:

- [Page data](data/exports/pages.csv): one row per attempt, raw headers, eligibility, exclusions, timestamps, redirects, and discovery information.
- [Site coverage](data/exports/sites.csv): all 150 sampled domains and per-site counts.
- [URL audit](data/exports/visits.csv): page attempts, redirects, and robots requests.
- [Raw per-site JSON](data/run/): original observations and collection metadata.
- [Data dictionary](DATA_DICTIONARY.md): schemas, denominators, normalization, and limitations.
- [Website inventory](WEBSITES.md), [process log](PROCESS.md), and [sources](SOURCES.md).
- [ZIP handoff](artifacts/netsec-data-handoff.zip) and [ZIP checksum](artifacts/SHA256SUMS).

The frozen ranking frame, sample seed, original ranking ZIP, permanent list ID, and source hashes are retained. The professor's feedback is reflected in the increased site/page budgets, recursive section-diverse selection, and strict origin checks. The sample is rank-stratified with equal allocation; do not interpret unweighted percentages as whole-web prevalence.

## Reproduce offline exports and checks

Python 3.9+; standard library only. From the repository root:

```sh
python3 -B -m unittest discover -s tests -v
python3 -B -m netsec.analyze
python3 -B -m netsec.validate
python3 -B -m netsec.inventory
python3 -B -m netsec.package
```

`-B` avoids writing Python bytecode to system cache directories. Export and validation commands make no network requests. The ZIP contains an internal SHA-256 manifest for its payload files.

## Reproduce sample selection

```sh
python3 -B -m netsec.prepare data/tranco-original.zip --output /tmp/netsec-reproduced-sample.csv
```

The resulting sample CSV should match `data/sample.csv` exactly. The archived download defines this run's sampling frame; downloading “latest” later will select a different ranking.

## Run a new live collection

```sh
python3 -B -m netsec.collect --sample data/sample.csv --output data/new-run --pages 40 --workers 12
python3 -B -m netsec.analyze --run data/new-run --output data/new-exports
python3 -B -m netsec.validate --run data/new-run --output data/new-exports
```

Live collection requires network access. It uses bounded GET requests, public HTTPS origins, robots checks, a 0.5-second minimum host delay, longer declared delays, no authentication, and no JavaScript. Subsequent page requests are locked to the canonical origin. `--help` lists budgets. Existing completed site files are skipped when resuming the same configuration; use a new directory when changing source or settings. The archived run used the source snapshot in `data/run/collector_source.py`; current code additionally hardens robots matching. Export review handles the recorded run's affected observations transparently.

The raw dataset includes a diagnostic pilot in `data/pilot_robots_redirect/`, excluded from primary exports. Review exclusions, incomplete coverage, bot/challenge heuristics, and the limits of textual header comparison are documented in the data dictionary. Header differences alone do not demonstrate security vulnerabilities.
