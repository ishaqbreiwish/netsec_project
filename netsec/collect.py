"""Bounded, robots-aware, HTTPS same-origin public-page collector (stdlib only)."""
import argparse
import concurrent.futures
import csv
import hashlib
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
import urllib.robotparser
from collections import Counter
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit
from .robots import robots_pattern_decision

UA = 'HeaderConsistencyResearch/1.0 (public-page academic measurement; no login)'
HEADERS = ['content-security-policy', 'content-security-policy-report-only', 'strict-transport-security']
SKIP_EXT = re.compile(r'\.(?:pdf|zip|gz|png|jpe?g|gif|svg|webp|ico|mp[34]|woff2?|css|js|xml|json|exe|dmg|csv|txt)$', re.I)
SENSITIVE = re.compile(r'/(?:logout|signout|sign-out|delete|remove|checkout|cart|login|signin|sign-in|register|signup|unsubscribe)(?:[/.]|$)', re.I)


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(url):
    try:
        s = urlsplit(url)
        if s.scheme.lower() != 'https' or s.username or s.password or s.port not in (None, 443):
            return None
        host = s.hostname.encode('idna').decode('ascii').lower()
        return urlunsplit(('https', host, s.path or '/', s.query, ''))
    except (ValueError, AttributeError, UnicodeError):
        return None


def origin(url):
    s = urlsplit(url)
    return s.scheme, s.hostname, s.port or 443


def public_host(host):
    answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not answers or any(not ipaddress.ip_address(a[4][0]).is_global for a in answers):
        raise ValueError('non-public destination')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.base = None
        self.meta_csp = []
        self.title = ''
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'a' and a.get('href'):
            self.links.append(a['href'])
        if tag == 'base' and self.base is None:
            self.base = a.get('href')
        if tag == 'meta' and a.get('http-equiv', '').lower() == 'content-security-policy':
            self.meta_csp.append(a.get('content', ''))
        if tag == 'title':
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == 'title':
            self.in_title = False

    def handle_data(self, text):
        if self.in_title:
            self.title += text


def candidate(href, base, site_origin):
    url = canonical(urljoin(base, href))
    if not url or origin(url) != site_origin:
        return None
    s = urlsplit(url)
    # No query variants, forms, assets, or obvious state-changing/account paths.
    if s.query or SKIP_EXT.search(s.path) or SENSITIVE.search(s.path):
        return None
    return url


def section(url):
    return next((x for x in urlsplit(url).path.split('/') if x), '/')


def priority(item, visits):
    url, depth, parent, seq = item
    # Round-robin path sections; within each, prefer depth not yet sampled.
    return visits[section(url)], visits['depth:' + str(depth)], depth, seq


class Client:
    def __init__(self, args):
        self.args = args
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        self.robots = {}
        self.robots_text = {}
        self.last = {}
        self.events = []

    def request(self, url, delay=None):
        host = urlsplit(url).hostname
        public_host(host)
        interval = max(self.args.delay, delay or 0)
        time.sleep(max(0, interval - (time.monotonic() - self.last.get(host, 0))))
        self.last[host] = time.monotonic()
        req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1', 'Accept-Encoding': 'identity'})
        try:
            response = self.opener.open(req, timeout=self.args.timeout)
        except urllib.error.HTTPError as e:
            response = e
        with response:
            headers = response.headers
            status = response.code
            # Redirect bodies are irrelevant; all reads have an explicit cap.
            body = response.read(self.args.max_bytes + 1) if status not in (301, 302, 303, 307, 308) else b''
        return status, headers, body

    def allowed(self, url):
        key = origin(url)
        if key not in self.robots:
            robots_url = f'https://{key[1]}/robots.txt'
            try:
                current = robots_url
                redirects = []
                for _ in range(6):
                    status, headers, body = self.request(current)
                    if status not in (301, 302, 303, 307, 308):
                        break
                    target = canonical(urljoin(current, headers.get('Location', '')))
                    root = key[1][4:] if key[1].startswith('www.') else key[1]
                    if not target or urlsplit(target).hostname not in (root, 'www.' + root):
                        break
                    redirects.append({'url': current, 'status': status, 'location': target})
                    current = target
                parser = urllib.robotparser.RobotFileParser()
                if status == 200 and len(body) <= self.args.max_bytes:
                    text = body.decode('utf-8', 'replace')
                    parser.parse(text.splitlines())
                    self.robots_text[key] = text
                    allowed = parser
                    reason = 'parsed'
                elif status in (404, 410):
                    allowed, reason = True, 'not_found'
                else:
                    allowed, reason = False, f'conservative_block_status_{status}'
                self.robots[key] = allowed
                self.events.append({'url': robots_url, 'timestamp': now(), 'status': status,
                                    'decision': reason, 'final_url': current, 'redirect_chain': redirects, 'body_sha256': hashlib.sha256(body).hexdigest(),
                                    'body': body[:self.args.max_bytes].decode('utf-8', 'replace')})
            except Exception as e:
                self.robots[key] = False
                self.events.append({'url': robots_url, 'timestamp': now(), 'decision': 'conservative_block_error', 'error': str(e)})
        rule = self.robots[key]
        if isinstance(rule, bool):
            return rule, self.args.delay
        supplemental, _ = robots_pattern_decision(self.robots_text.get(key, ''), url)
        declared_delays = [float(m.group(1)) for m in re.finditer(r'^crawl-delay:\s*([0-9]+(?:\.[0-9]+)?)', self.robots_text.get(key, ''), re.I | re.M)]
        rate = rule.request_rate(UA)
        rate_delay = rate.seconds / rate.requests if rate and rate.requests else 0
        return rule.can_fetch(UA, url) and supplemental, max([rule.crawl_delay(UA) or 0, self.args.delay, rate_delay] + declared_delays)

    def fetch(self, url, domain, locked=None):
        chain = []
        current = url
        for hop in range(9):
            allowed, delay = self.allowed(current)
            if not allowed:
                return {'error': 'robots_denied', 'final_url': current, 'redirect_chain': chain}, b''
            started = now()
            status, headers, body = self.request(current, delay)
            record = {'timestamp': started, 'final_url': current, 'status': status,
                      'content_type': headers.get('Content-Type', ''),
                      'headers': {h: headers.get_all(h, []) for h in HEADERS},
                      'body_bytes': len(body), 'truncated': len(body) > self.args.max_bytes,
                      'body_sha256': hashlib.sha256(body[:self.args.max_bytes]).hexdigest(),
                      'redirect_chain': list(chain)}
            if status not in (301, 302, 303, 307, 308):
                return record, body[:self.args.max_bytes]
            target = canonical(urljoin(current, headers.get('Location', '')))
            chain.append({'url': current, 'status': status, 'location': headers.get('Location', ''), 'headers': record['headers']})
            # Homepage bootstrapping permits ONLY apex <-> www. All subsequent requests lock to origin.
            valid = target and (origin(target) == locked if locked else urlsplit(target).hostname in (domain, 'www.' + domain))
            if not valid:
                record.update(error='redirect_out_of_scope', redirect_chain=chain)
                return record, b''
            current = target
        return {'error': 'redirect_limit', 'final_url': current, 'redirect_chain': chain}, b''


def crawl_site(site, args):
    domain = site['domain']
    client = Client(args)
    rows, pending, seen, finals = [], [(f'https://{domain}/', 0, '', 0)], set(), set()
    visits = Counter()
    locked = None
    successes = 0
    start = time.monotonic()
    while pending and successes < args.pages and len(rows) < args.max_attempts:
        if time.monotonic() - start > args.site_seconds:
            break
        pending.sort(key=lambda x: priority(x, visits))
        url, depth, parent, seq = pending.pop(0)
        if url in seen:
            continue
        seen.add(url)
        visits[section(url)] += 1
        visits['depth:' + str(depth)] += 1
        row = dict(site, requested_url=url, depth=depth, parent_url=parent, attempt=len(rows) + 1, timestamp=now())
        try:
            result, body = client.fetch(url, domain, locked)
            row.update(result)
            if not rows and not row.get('error'):
                locked = origin(row['final_url'])
            html = row.get('content_type', '').split(';')[0].strip().lower() in ('text/html', 'application/xhtml+xml')
            eligible = not row.get('error') and 200 <= row.get('status', 0) < 300 and html and not row.get('truncated')
            parser = Links()
            if eligible:
                parser.feed(body.decode('utf-8', 'replace'))
            challenge = bool(re.search(r'just a moment|attention required|access denied|verify (?:you are|you.re) human|security verification|robot or human', parser.title, re.I))
            row.update(html=html, challenge_suspected=challenge, meta_csp=parser.meta_csp, title=parser.title[:300])
            row['duplicate_final'] = row.get('final_url') in finals
            row['eligible'] = eligible and not challenge and not row['duplicate_final']
            if row['eligible']:
                successes += 1
                finals.add(row['final_url'])
                if depth < args.max_depth:
                    base = urljoin(row['final_url'], parser.base) if parser.base else row['final_url']
                    for href in parser.links:
                        target = candidate(href, base, locked)
                        if target and target not in seen and len(pending) < 2000 and all(x[0] != target for x in pending):
                            pending.append((target, depth + 1, row['final_url'], len(pending) + len(rows) * 2000))
            if row.get('status') == 429:
                row['stop_reason'] = 'rate_limited'
                rows.append(row)
                break
        except Exception as e:
            row.update(error=f'{type(e).__name__}: {e}', eligible=False)
        rows.append(row)
        if len(rows) == 1 and not row.get('eligible'):
            break
    reason = 'page_budget' if successes >= args.pages else 'attempt_budget' if len(rows) >= args.max_attempts else 'time_budget' if pending and time.monotonic()-start > args.site_seconds else 'frontier_exhausted'
    return {'site': site, 'rows': rows, 'robots': client.events, 'eligible_pages': successes,
            'canonical_origin': list(locked) if locked else None, 'stop_reason': reason,
            'elapsed_seconds': round(time.monotonic() - start, 2)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sample', type=Path, default=Path('data/sample.csv'))
    p.add_argument('--output', type=Path, default=Path('data/run'))
    p.add_argument('--pages', type=int, default=40)
    p.add_argument('--max-depth', type=int, default=5)
    p.add_argument('--max-attempts', type=int, default=80)
    p.add_argument('--workers', type=int, default=12)
    p.add_argument('--delay', type=float, default=0.5)
    p.add_argument('--timeout', type=float, default=10)
    p.add_argument('--site-seconds', type=float, default=240)
    p.add_argument('--max-bytes', type=int, default=2_000_000)
    a = p.parse_args()
    if min(a.pages, a.max_depth, a.max_attempts, a.workers, a.timeout, a.site_seconds, a.max_bytes) <= 0 or a.delay < 0:
        p.error('budgets must be positive; delay must be nonnegative')
    sites = list(csv.DictReader(a.sample.open()))
    if any(not re.fullmatch(r'[a-zA-Z0-9.-]+', s['domain']) or '..' in s['domain'] for s in sites):
        p.error('invalid domain in sample')
    a.output.mkdir(parents=True, exist_ok=True)
    metadata = a.output / 'metadata.json'
    if metadata.exists():
        previous = json.loads(metadata.read_text())
        config = {k: str(v) if isinstance(v, Path) else v for k, v in vars(a).items()}
        if previous.get('source_sha256') and previous['source_sha256'] != {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')}:
            p.error('source changed since this run began; use a new output directory')
        if previous['config'] != config or previous['sample_sha256'] != hashlib.sha256(a.sample.read_bytes()).hexdigest():
            p.error('existing run has different configuration or sample; use a new output directory')
    else:
        metadata.write_text(json.dumps({'started_at': now(), 'user_agent': UA,
            'sample_sha256': hashlib.sha256(a.sample.read_bytes()).hexdigest(),
            'python_version': sys.version,
            'source_sha256': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')},
            'config': {k: str(v) if isinstance(v, Path) else v for k, v in vars(a).items()}}, indent=2) + '\n')
    todo = [s for s in sites if not (a.output / (s['domain'] + '.json')).exists()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
        futures = {pool.submit(crawl_site, s, a): s for s in todo}
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            path = a.output / (result['site']['domain'] + '.json')
            tmp = path.with_suffix('.tmp')
            tmp.write_text(json.dumps(result, indent=2) + '\n')
            tmp.replace(path)
            print(f"{result['site']['domain']}: {result['eligible_pages']} eligible / {len(result['rows'])} attempts ({result['stop_reason']})", flush=True)
    meta = json.loads(metadata.read_text())
    meta['last_completed_at'] = now()
    metadata.write_text(json.dumps(meta, indent=2) + '\n')

if __name__ == '__main__':
    main()
