"""Offline integrity checks and robots-pattern review; no network requests."""
import argparse
import csv
import hashlib
import io
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from .collect import HEADERS, origin
from .analyze import write_csv
from .robots import robots_pattern_decision
from .review import apply_review


def validate(sample_path, run, archive, provenance):
    sample = list(csv.DictReader(sample_path.open()))
    lookup = {s['domain']: s for s in sample}
    errors, warnings, reviews = [], [], []
    def check(condition, message):
        if not condition:
            errors.append(message)
    meta = json.loads((run/'metadata.json').read_text())
    check(meta['sample_sha256'] == hashlib.sha256(sample_path.read_bytes()).hexdigest(), 'sample hash differs from run metadata')
    prov = json.loads(provenance.read_text())
    blob = archive.read_bytes()
    check(prov['archive_sha256'] == hashlib.sha256(blob).hexdigest(), 'ranking archive hash mismatch')
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        ranking_bytes = z.read(z.namelist()[0])
        ranking = dict(csv.reader(io.StringIO(ranking_bytes.decode('utf-8'))))
    if prov.get('verified_csv_sha256'):
        check(prov['verified_csv_sha256'] == hashlib.sha256(ranking_bytes).hexdigest(), 'permanent-list CSV hash mismatch')
    if meta.get('collector_source_snapshot'):
        check(hashlib.sha256(Path(meta['collector_source_snapshot']).read_bytes()).hexdigest() == meta['collector_source_snapshot_sha256'], 'collector source snapshot hash mismatch')
    for s in sample:
        check(ranking.get(s['rank']) == s['domain'], f'rank mismatch: {s}')
        lo, hi = map(int, s['stratum'].split('-'))
        check(lo <= int(s['rank']) <= hi, f'rank outside stratum: {s}')
    check(len(lookup) == len(sample), 'duplicate sampled domain')
    files = {p.stem: p for p in run.glob('*.json') if p.name != 'metadata.json'}
    check('last_completed_at' in meta, 'run not marked complete')
    check(set(files) == set(lookup), 'missing or unexpected site result files')
    total = eligible_total = cleaned_total = 0
    for domain, path in sorted(files.items()):
        data = json.loads(path.read_text())
        check(data['site'] == lookup.get(domain), f'{domain}: identity differs from sample')
        rows = data['rows']
        eligible = [r for r in rows if r.get('eligible')]
        total += len(rows)
        eligible_total += len(eligible)
        cleaned_total += sum(r['eligible'] for r in apply_review(json.loads(path.read_text()))['rows'])
        check(len(rows) <= meta['config']['max_attempts'], f'{domain}: attempt cap')
        check(len(eligible) <= meta['config']['pages'], f'{domain}: page cap')
        check(data['eligible_pages'] == len(eligible), f'{domain}: eligible count')
        check(len({r['final_url'] for r in eligible}) == len(eligible), f'{domain}: duplicate eligible final URL')
        locked = tuple(data['canonical_origin']) if data['canonical_origin'] else None
        for r in rows:
            if r['depth'] > 0:
                check(origin(r['requested_url']) == locked, f'{domain}: interior requested URL left origin')
            check(r['depth'] <= meta['config']['max_depth'], f'{domain}: depth cap')
            check(datetime.fromisoformat(r['timestamp']).tzinfo is not None, f'{domain}: timestamp timezone')
            if r.get('eligible'):
                check(origin(r['final_url']) == locked, f'{domain}: eligible page off origin')
                check(200 <= r['status'] < 300 and r['html'] and not r.get('error') and not r['truncated'] and not r['challenge_suspected'], f'{domain}: invalid eligibility')
                check(all(isinstance(r['headers'][h], list) for h in HEADERS), f'{domain}: header field arrays')
            for hop in r.get('redirect_chain', []):
                check(urlsplit(hop['url']).hostname in (domain, 'www.' + domain), f'{domain}: followed off-site redirect hop')
                if r['depth'] > 0:
                    check(origin(hop['url']) == locked, f'{domain}: interior redirect hop left origin')
            # Standard-library robotparser does not implement wildcard/end-anchor rules.
            # Audit these independently and expose potential exclusions to data consumers.
            if r.get('eligible'):
                events = [e for e in data['robots'] if origin(e['url']) == origin(r['final_url'])]
                if events and events[0]['decision'] == 'parsed':
                    event = events[0]
                    allowed, rule = robots_pattern_decision(event['body'], r['final_url'])
                    if not allowed:
                        reviews.append(dict(domain=domain, url=r['final_url'], matched_disallow=rule,
                                            issue='supplemental_robots_pattern_disallow', collector_eligible=True))
        for e in data['robots']:
            if e['decision'] == 'parsed' and any('*' in line.partition(':')[2] or '$' in line.partition(':')[2] for line in e['body'].splitlines() if line.lower().startswith(('allow:', 'disallow:'))):
                warnings.append(f'{domain}: robots contains wildcard/end-anchor rules; see supplemental audit')
    return {'passed': not errors, 'sampled_domains': len(sample), 'result_files': len(files),
            'page_attempts': total, 'run_marked_complete': 'last_completed_at' in meta, 'collector_eligible_pages': eligible_total, 'cleaned_eligible_pages': cleaned_total,
            'errors': errors, 'warnings': sorted(set(warnings)),
            'robots_pattern_review_pages': len(reviews)}, reviews


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sample', type=Path, default=Path('data/sample.csv'))
    p.add_argument('--run', type=Path, default=Path('data/run'))
    p.add_argument('--archive', type=Path, default=Path('data/tranco-original.zip'))
    p.add_argument('--provenance', type=Path, default=Path('data/sample.provenance.json'))
    p.add_argument('--output', type=Path, default=Path('data/exports'))
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    report, reviews = validate(a.sample, a.run, a.archive, a.provenance)
    (a.output/'validation.json').write_text(json.dumps(report, indent=2) + '\n')
    write_csv(a.output/'robots_review.csv', reviews, ['domain', 'url', 'matched_disallow', 'issue', 'collector_eligible'])
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report['passed'] else 1)

if __name__ == '__main__':
    main()
