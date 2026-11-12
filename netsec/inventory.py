"""Produce the requested readable website inventory from descriptive exports."""
import argparse
import csv
import json
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--exports', type=Path, default=Path('data/exports'))
    p.add_argument('--output', type=Path, default=Path('WEBSITES.md'))
    a = p.parse_args()
    rows = sorted(csv.DictReader((a.exports/'sites.csv').open()), key=lambda r: int(r['rank']))
    text = ['# Website collection inventory', '',
            'All sampled domains are listed, including failed and denied attempts. “Eligible” below means cleaned export eligibility, not proof that a site is secure. A zero-page domain may have received only a robots request; see its raw JSON and the visit audit for what actually happened.', '',
            'Page-level URLs, statuses, redirects, UTC record times, and exclusions: `data/exports/visits.csv` and `data/exports/pages.csv`. Source/protocol websites consulted are listed in `SOURCES.md` and `PROCESS.md`. The diagnostic pilot used the same domain sample and remains in `data/pilot_robots_redirect/`.', '',
            '| Tranco rank | Sampled domain | Canonical origin | Page attempts | Cleaned eligible pages | Comparable | Stop reason |',
            '| --- | --- | --- | --- | --- | --- | --- |']
    for r in rows:
        parsed = json.loads(r['canonical_origin']) if r['canonical_origin'] else None
        canonical = f'{parsed[0]}://{parsed[1]}' if parsed else 'not established'
        text.append(f"| {r['rank']} | {r['domain']} | {canonical} | {r['attempted_pages']} | {r['eligible_pages']} | {r['comparable']} | {r['stop_reason']} |")
    a.output.write_text('\n'.join(text) + '\n')
    print(f'Wrote {len(rows)} domains to {a.output}')

if __name__ == '__main__':
    main()
