"""Conservative supplemental robots matching for wildcard and group precedence checks."""
import re
from urllib.parse import urlsplit


def robots_pattern_decision(text, url, agent='headerconsistencyresearch'):
    """Supplemental common wildcard/$ audit, not a full RFC 9309 parser."""
    groups, agents, rules = [], [], []
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        key, sep, value = line.partition(':')
        if not sep:
            continue
        key, value = key.strip().lower(), value.strip()
        if key == 'user-agent':
            if rules:
                groups.append((agents, rules))
                agents, rules = [], []
            agents.append(value.lower())
        elif key in ('allow', 'disallow') and agents and value:
            rules.append((key, value))
    if agents:
        groups.append((agents, rules))
    matches = [(max([len(a) for a in agents if a != '*' and a in agent] or [0]), rules)
               for agents, rules in groups if '*' in agents or any(a in agent for a in agents)]
    best = max([m[0] for m in matches] or [-1])
    target = urlsplit(url).path or '/'
    if urlsplit(url).query:
        target += '?' + urlsplit(url).query
    matching = []
    for strength, rules in matches:
        if strength != best:
            continue
        for kind, pattern in rules:
            end = pattern.endswith('$')
            expr = '^' + '.*'.join(re.escape(p) for p in (pattern[:-1] if end else pattern).split('*')) + ('$' if end else '')
            if re.search(expr, target):
                matching.append((len(pattern.replace('*', '').rstrip('$')), kind == 'allow', pattern))
    if not matching:
        return True, ''
    winner = max(matching)
    return winner[1], winner[2]

