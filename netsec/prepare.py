"""Freeze a deterministic rank-stratified sample from a downloaded Tranco ZIP."""
import argparse
import csv
import hashlib
import io
import json
import random
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('archive', type=Path)
    p.add_argument('--output', type=Path, default=Path('data/sample.csv'))
    p.add_argument('--sites', type=int, default=150)
    p.add_argument('--seed', type=int, default=20261112)
    p.add_argument('--source-url', default='https://tranco-list.eu/top-1m.csv.zip')
    a = p.parse_args()
    if a.sites < 3 or a.sites > 1000:
        p.error('sites must be between 3 and 1000')
    blob = a.archive.read_bytes()
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        rows = list(csv.reader(io.TextIOWrapper(z.open(z.namelist()[0]))))[:10000]
    rng = random.Random(a.seed)
    selected = []
    for i, (lo, hi) in enumerate([(1, 100), (101, 1000), (1001, 10000)]):
        pool = [r for r in rows if lo <= int(r[0]) <= hi]
        n = a.sites // 3 + (i < a.sites % 3)
        selected.extend((rank, domain, f'{lo}-{hi}') for rank, domain in rng.sample(pool, n))
    selected.sort(key=lambda r: int(r[0]))
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open('w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['rank', 'domain', 'stratum'])
        w.writerows(selected)
    # Preserve the exact sampling frame rather than relying on a changing latest URL.
    with a.output.with_name('ranking_top10000.csv').open('w', newline='') as f:
        csv.writer(f).writerows(rows)
    a.output.with_suffix('.provenance.json').write_text(json.dumps({
        'retrieved_at': datetime.now(timezone.utc).isoformat(),
        'source_url': a.source_url, 'archive_sha256': hashlib.sha256(blob).hexdigest(),
        'seed': a.seed, 'sites': a.sites, 'strata': ['1-100', '101-1000', '1001-10000'],
        'design': 'equal allocation without replacement within rank strata; descriptive, unweighted results'
    }, indent=2) + '\n')

if __name__ == '__main__':
    main()
