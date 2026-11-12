"""Conservative post-collection exclusions; raw observations remain immutable."""
from urllib.parse import urlsplit
from .collect import SENSITIVE, origin
from .robots import robots_pattern_decision


def apply_review(data):
    events = {origin(e['url']): e for e in data['robots']}
    for row in data['rows']:
        row['collector_eligible'] = bool(row.get('eligible'))
        reasons = []
        if row['collector_eligible']:
            visited = [h['url'] for h in row.get('redirect_chain', [])] + [row['final_url']]
            for url in visited:
                event = events.get(origin(url))
                if event and event['decision'] == 'parsed':
                    allowed, rule = robots_pattern_decision(event['body'], url)
                    if not allowed:
                        reasons.append('supplemental_robots_disallow:' + rule)
            if SENSITIVE.search(urlsplit(row['final_url']).path):
                reasons.append('account_or_state_changing_final_path')
        row['review_exclusions'] = sorted(set(reasons))
        row['eligible'] = row['collector_eligible'] and not reasons
    return data
