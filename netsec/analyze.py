"""Export auditable CSV data and descriptive counts, without writing a report."""
import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from .collect import HEADERS, origin
from .review import apply_review

NONCE = re.compile(r"'nonce-[^'\s]+'", re.I)


def signature(values, kind='raw'):
    """Conservative textual fingerprints; not browser-policy equivalence."""
    if kind == 'raw':
        return tuple(values)
    if kind == 'csp':
        # Preserve policy and directive order, case, hashes, URLs, report destinations.
        return tuple(' '.join(NONCE.sub("'nonce-<redacted>'", v).split()) for v in values)
    if kind == 'hsts':
        result = []
        for v in values:
            directives = []
            for item in v.split(';'):
                name, sep, value = item.strip().partition('=')
                directives.append(name.lower() + (sep + value.strip() if sep else ''))
            result.append(';'.join(directives))
        return tuple(result)
    raise ValueError(kind)


def hsts_details(values):
    if not values:
        return 'absent', ''
    # RFC 6797: only the first field is processed; preserve all fields in the raw data.
    directives = [part.strip() for part in values[0].split(';')]
    names = [p.partition('=')[0].lower() for p in directives]
    ages = [p.partition('=')[2].strip().strip('"') for p in directives if p.partition('=')[0].lower() == 'max-age']
    if len(set(names)) != len(names) or len(ages) != 1 or not re.fullmatch(r'[0-9]+', ages[0]):
        return 'invalid_or_ambiguous', ''
    # This is a screening label, not a full RFC grammar validator.
    return ('zero_max_age' if int(ages[0]) == 0 else 'positive_max_age'), ages[0]


def write_csv(path, rows, fields=None):
    if fields is None:
        fields = list(dict.fromkeys(k for row in rows for k in row))
    with path.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list, tuple)) else v for k, v in row.items()})


def describe(run):
    pages, sites, visits, examples, curves = [], [], [], [], []
    files = sorted(p for p in run.glob('*.json') if p.name != 'metadata.json')
    for path in files:
        data = apply_review(json.loads(path.read_text()))
        identity = data['site']
        all_rows = data['rows']
        eligible = [r for r in all_rows if r.get('eligible')]
        home = all_rows[0] if all_rows and all_rows[0].get('eligible') else None
        comparable = home is not None and len(eligible) >= 2
        s = dict(identity, attempted_pages=len(all_rows), eligible_pages=len(eligible),
                 collector_eligible_pages=data['eligible_pages'], reviewed_excluded_pages=sum(bool(r['review_exclusions']) for r in all_rows),
                 comparable=comparable, homepage_eligible=home is not None,
                 canonical_origin=data['canonical_origin'], stop_reason=data['stop_reason'],
                 max_discovery_depth=max((r['depth'] for r in eligible), default=0),
                 path_sections=len({r['final_url'].split('/')[3] for r in eligible}),
                 elapsed_seconds=data['elapsed_seconds'])
        for key, alias in [(HEADERS[0], 'csp'), (HEADERS[1], 'csp_report_only'), (HEADERS[2], 'hsts')]:
            values = [r.get('headers', {}).get(key, []) for r in eligible]
            s[alias + '_pages_present'] = sum(bool(v) for v in values)
            s[alias + '_home_present'] = bool(home.get('headers', {}).get(key)) if home else ''
            kind = 'hsts' if alias == 'hsts' else 'csp'
            home_values = home.get('headers', {}).get(key, []) if home else []
            interior = [r for r in eligible if r is not home]
            s[alias + '_presence_mismatch'] = any(bool(r['headers'][key]) != bool(home_values) for r in interior) if comparable else ''
            s[alias + '_raw_mismatch'] = any(signature(r['headers'][key]) != signature(home_values) for r in interior) if comparable else ''
            s[alias + '_normalized_mismatch'] = any(signature(r['headers'][key], kind) != signature(home_values, kind) for r in interior) if comparable else ''
            s[alias + '_home_present_interior_absent'] = bool(home_values) and any(not r['headers'][key] for r in interior) if comparable else ''
            s[alias + '_home_absent_interior_present'] = not home_values and any(r['headers'][key] for r in interior) if comparable else ''
            s[alias + '_distinct_normalized_deliveries'] = len({signature(v, kind) for v in values})
            if comparable:
                example = next((r for r in interior if signature(r['headers'][key], kind) != signature(home_values, kind)), None)
                if example:
                    examples.append(dict(identity, header=key, homepage_url=home['final_url'],
                                         interior_url=example['final_url'], depth=example['depth'],
                                         homepage_headers=home_values, interior_headers=example['headers'][key]))
        sites.append(s)
        for row in all_rows:
            headers = row.get('headers', {})
            hsts_state, max_age = hsts_details(headers.get(HEADERS[2], []))
            out = {k: row.get(k, '') for k in ('rank', 'domain', 'stratum', 'requested_url', 'final_url', 'timestamp', 'attempt', 'depth', 'parent_url', 'status', 'content_type', 'html', 'eligible', 'collector_eligible', 'review_exclusions', 'error', 'truncated', 'duplicate_final', 'challenge_suspected', 'title', 'body_bytes', 'body_sha256', 'meta_csp', 'redirect_chain')}
            out['is_homepage'] = row is all_rows[0]
            for key, alias in [(HEADERS[0], 'csp'), (HEADERS[1], 'csp_report_only'), (HEADERS[2], 'hsts')]:
                val = headers.get(key, [])
                out[alias + '_headers'] = val
                out[alias + '_present'] = bool(val)
                out[alias + '_normalized'] = signature(val, 'hsts' if alias == 'hsts' else 'csp')
            out.update(hsts_screen=hsts_state, hsts_max_age=max_age)
            pages.append(out)
            for hop in row.get('redirect_chain', []):
                visits.append(dict(identity, kind='redirect', url=hop['url'], status=hop['status'], destination=hop['location'], timestamp=row['timestamp'], timestamp_kind='page_record_time'))
            if not row.get('redirect_chain') or row.get('final_url') != row['redirect_chain'][-1]['url']:
                visits.append(dict(identity, kind='page_attempt', url=row.get('final_url', row['requested_url']), status=row.get('status', ''), destination='', timestamp=row['timestamp'], timestamp_kind='page_record_time', error=row.get('error', '')))
        for event in data['robots']:
            chain = event.get('redirect_chain', [])
            for hop in chain:
                visits.append(dict(identity, kind='robots_redirect', url=hop['url'], status=hop['status'], destination=hop['location'], timestamp=event['timestamp'], timestamp_kind='robots_event_time', decision=event['decision']))
            # A robots redirect-limit event may name a target never fetched.
            if not (len(chain) >= 6 and event.get('status') in (301, 302, 303, 307, 308)):
                visits.append(dict(identity, kind='robots_final' if chain else 'robots', url=event.get('final_url', event['url']), status=event.get('status', ''), destination='', timestamp=event['timestamp'], timestamp_kind='robots_event_time', decision=event['decision'], error=event.get('error', '')))
        # Fixed cohort for a valid paired page-budget comparison: full 40-page sites only.
        if comparable and len(eligible) >= 40:
            for budget in (1, 5, 10, 20, 40):
                subset = eligible[:budget]
                for key, alias in [(HEADERS[0], 'csp'), (HEADERS[2], 'hsts')]:
                    curves.append(dict(identity, page_budget=budget, header=alias,
                        normalized_difference_detected=any(signature(r['headers'][key], alias) != signature(home['headers'][key], alias) for r in subset),
                        presence_difference_detected=any(bool(r['headers'][key]) != bool(home['headers'][key]) for r in subset)))
    return pages, sites, visits, examples, curves


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', type=Path, default=Path('data/run'))
    p.add_argument('--output', type=Path, default=Path('data/exports'))
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    pages, sites, visits, examples, curves = describe(a.run)
    for name, rows, fields in [('pages', pages, ['domain', 'requested_url', 'eligible']),
                               ('sites', sites, ['domain', 'eligible_pages', 'comparable']),
                               ('visits', visits, ['domain', 'kind', 'url']),
                               ('difference_examples', examples, ['domain', 'header', 'homepage_url', 'interior_url', 'homepage_headers', 'interior_headers']),
                               ('page_budget', curves, ['domain', 'page_budget', 'header', 'normalized_difference_detected', 'presence_difference_detected'])]:
        write_csv(a.output / (name + '.csv'), rows, None if rows else fields)
    eligible = [r for r in pages if r['eligible']]
    comparable = [s for s in sites if s['comparable']]
    summary = {'measured_domains': len(sites), 'attempted_pages': len(pages), 'eligible_pages': len(eligible),
               'domains_with_eligible_homepage': sum(s['homepage_eligible'] for s in sites),
               'review_excluded_pages': sum(bool(r['review_exclusions']) for r in pages),
               'comparable_domains': len(comparable), 'domains_with_40_pages': sum(s['eligible_pages'] >= 40 for s in sites),
               'errors': dict(Counter(r['error'].split(':')[0] for r in pages if r['error'])),
               'http_statuses': dict(Counter(str(r['status']) for r in pages)),
               'strata': {}, 'headers': {}}
    for stratum in sorted({s['stratum'] for s in sites}):
        group = [s for s in sites if s['stratum'] == stratum]
        summary['strata'][stratum] = {'sampled': len(group), 'eligible_homepage': sum(s['homepage_eligible'] for s in group), 'comparable': sum(s['comparable'] for s in group), 'eligible_pages': sum(s['eligible_pages'] for s in group)}
    for alias in ('csp', 'csp_report_only', 'hsts'):
        summary['headers'][alias] = {'eligible_page_denominator': len(eligible), 'pages_present': sum(r[alias + '_present'] for r in eligible),
            'eligible_homepage_denominator': summary['domains_with_eligible_homepage'], 'homepages_present': sum(s[alias + '_home_present'] is True for s in sites),
            'comparable_domain_denominator': len(comparable), **{metric: sum(s[alias + '_' + metric] is True for s in comparable) for metric in ('presence_mismatch', 'raw_mismatch', 'normalized_mismatch', 'home_present_interior_absent', 'home_absent_interior_present')}}
    (a.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    # Machine-readable audit hashes let teammates verify that exports came from these inputs.
    manifest = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(a.run.glob('*.json'))}
    (a.output / 'input_manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(summary, indent=2))

if __name__ == '__main__':
    main()
