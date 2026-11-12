import json
import tempfile
import unittest
from argparse import Namespace
from collections import Counter
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from netsec.collect import Client, HEADERS, Links, candidate, canonical, crawl_site, origin, priority
from netsec.analyze import describe, hsts_details, signature


def headers(**kwargs):
    h = Message()
    for k, v in kwargs.items():
        h[k.replace('_', '-')] = v
    return h


class URLTests(unittest.TestCase):
    def test_scope(self):
        base = 'https://example.com/'
        for href in ('https://evil.com/', '//sub.example.com/', 'http://example.com/',
                     'https://example.com:444/', 'https://u:p@example.com/', '/a?q=1', '/logout', '/doc.pdf'):
            self.assertIsNone(candidate(href, base, origin(base)), href)
        self.assertEqual(candidate('/about#team', base, origin(base)), 'https://example.com/about')
        self.assertEqual(canonical('https://EXAMPLE.com:443/#x'), base)

    def test_path_diversity_and_depth(self):
        visits = Counter({'news': 5, 'about': 0})
        a = ('https://example.com/news/a', 1, '', 0)
        b = ('https://example.com/about/b', 2, '', 1)
        self.assertLess(priority(b, visits), priority(a, visits))

    def test_html(self):
        p = Links()
        p.feed('<base href="/docs/"><a href="intro">x</a><meta http-equiv="Content-Security-Policy" content="default-src none"><title>Sample</title>')
        self.assertEqual(p.base, '/docs/')
        self.assertEqual(p.links, ['intro'])
        self.assertEqual(p.meta_csp, ['default-src none'])
        self.assertEqual(p.title, 'Sample')


class HeaderTests(unittest.TestCase):
    def test_nonce_only_normalization(self):
        a = ["script-src 'nonce-AAA' 'sha256-a'; report-uri /report"]
        b = ["script-src 'nonce-BBB' 'sha256-a'; report-uri /report"]
        self.assertNotEqual(signature(a), signature(b))
        self.assertEqual(signature(a, 'csp'), signature(b, 'csp'))
        self.assertNotEqual(signature(a, 'csp'), signature([a[0].replace('sha256-a', 'sha256-b')], 'csp'))
        self.assertNotEqual(signature(a, 'csp'), signature([a[0].replace('/report', '/other')], 'csp'))

    def test_duplicate_fields_retained(self):
        a = ["default-src 'self'", "script-src 'none'"]
        self.assertEqual(len(signature(a, 'csp')), 2)
        self.assertNotEqual(signature(a, 'csp'), signature(a[:1], 'csp'))

    def test_hsts_screen(self):
        self.assertEqual(hsts_details([]), ('absent', ''))
        self.assertEqual(hsts_details(['max-age=0']), ('zero_max_age', '0'))
        self.assertEqual(hsts_details(['max-age="123"; includeSubDomains']), ('positive_max_age', '123'))
        for value in ('max-age=-1', 'max-age=1; max-age=2', 'includeSubDomains'):
            self.assertEqual(hsts_details([value])[0], 'invalid_or_ambiguous')
        self.assertEqual(hsts_details(['max-age=0', 'max-age=100'])[1], '0')


class RedirectTests(unittest.TestCase):
    def setUp(self):
        self.args = Namespace(delay=0, timeout=1, max_bytes=1000)

    def client(self, responses):
        c = Client(self.args)
        c.allowed = lambda url: (True, 0)
        c.request = unittest.mock.Mock(side_effect=responses)
        return c

    def test_home_apex_www_only(self):
        c = self.client([(301, headers(Location='https://www.example.com/'), b''),
                         (200, headers(Content_Type='text/html'), b'ok')])
        record, _ = c.fetch('https://example.com/', 'example.com')
        self.assertEqual(record['final_url'], 'https://www.example.com/')
        self.assertEqual(c.request.call_count, 2)
        c = self.client([(302, headers(Location='https://other.example.com/'), b'')])
        record, _ = c.fetch('https://example.com/', 'example.com')
        self.assertEqual(record['error'], 'redirect_out_of_scope')
        self.assertEqual(c.request.call_count, 1)

    def test_locked_redirect_never_leaves_origin(self):
        c = self.client([(302, headers(Location='https://example.com/'), b'')])
        record, _ = c.fetch('https://www.example.com/x', 'example.com', origin('https://www.example.com/'))
        self.assertEqual(record['error'], 'redirect_out_of_scope')
        self.assertEqual(c.request.call_count, 1)

    def test_robots_redirect_and_denial(self):
        c = Client(self.args)
        c.request = unittest.mock.Mock(side_effect=[
            (301, headers(Location='https://www.example.com/robots.txt'), b''),
            (200, headers(), b'User-agent: *\nDisallow: /private\nCrawl-delay: 2\n')])
        self.assertEqual(c.allowed('https://example.com/private'), (False, 2))
        self.assertEqual(c.allowed('https://example.com/public'), (True, 2))
        self.assertEqual(c.request.call_count, 2)
        c = Client(self.args)
        c.request = unittest.mock.Mock(return_value=(503, headers(), b''))
        self.assertFalse(c.allowed('https://example.com/')[0])


class AnalysisTests(unittest.TestCase):
    def test_failed_site_excluded_and_missing_diff_included(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            def row(url, hs, attempt, eligible=True):
                return dict(domain='example.com', rank='1', stratum='1-100', requested_url=url,
                            final_url=url, eligible=eligible, timestamp='2026-01-01', depth=attempt-1,
                            attempt=attempt, status=200, headers={HEADERS[0]: hs, HEADERS[1]: [], HEADERS[2]: []})
            site = dict(site={'domain': 'example.com', 'rank': '1', 'stratum': '1-100'},
                        canonical_origin=['https', 'example.com', 443], stop_reason='frontier_exhausted',
                        elapsed_seconds=1, robots=[], eligible_pages=2, rows=[row('https://example.com/', ["default-src 'self'"], 1), row('https://example.com/a', [], 2)])
            (path/'example.com.json').write_text(json.dumps(site))
            bad = dict(site, site={'domain': 'bad.com', 'rank': '2', 'stratum': '1-100'},
                       eligible_pages=0, rows=[dict(row('https://bad.com/', [], 1, False), error='robots_denied')])
            (path/'bad.com.json').write_text(json.dumps(bad))
            pages, sites, visits, examples, curves = describe(path)
            self.assertEqual(sum(s['comparable'] for s in sites), 1)
            good = next(s for s in sites if s['domain'] == 'example.com')
            self.assertTrue(good['csp_presence_mismatch'])
            self.assertTrue(good['csp_home_present_interior_absent'])
            self.assertEqual(len(examples), 1)
            self.assertEqual(curves, [])

    def test_duplicate_final_is_not_extra_page(self):
        args = Namespace(delay=0, timeout=1, max_bytes=1000, pages=10, max_depth=5,
                         max_attempts=10, site_seconds=10)
        def fake(self, url, domain, locked=None):
            body = b'<a href="/a">a</a><a href="/b">b</a>'
            return dict(final_url='https://example.com/', status=200, content_type='text/html',
                        headers={k: [] for k in HEADERS}, truncated=False), body
        with patch.object(Client, 'fetch', fake):
            data = crawl_site({'domain': 'example.com', 'rank': '1', 'stratum': '1-100'}, args)
        self.assertEqual(data['eligible_pages'], 1)
        self.assertEqual(len(data['rows']), 3)
        self.assertTrue(data['rows'][1]['duplicate_final'])



class RobotsAuditTests(unittest.TestCase):
    def test_wildcards_end_anchor_and_allow_tie(self):
        from netsec.robots import robots_pattern_decision as allowed
        policy = 'User-agent: *\nDisallow: /archive/*\nAllow: /archive/public\nDisallow: /end$\n'
        self.assertFalse(allowed(policy, 'https://example.com/archive/2026')[0])
        self.assertTrue(allowed(policy, 'https://example.com/archive/public')[0])
        self.assertFalse(allowed(policy, 'https://example.com/end')[0])
        self.assertTrue(allowed(policy, 'https://example.com/ending')[0])
        self.assertTrue(allowed('User-agent: *\nDisallow: /a\nAllow: /a', 'https://example.com/a')[0])

    def test_specific_agent_and_merge(self):
        from netsec.robots import robots_pattern_decision as allowed
        policy = 'User-agent: *\nDisallow: /\nUser-agent: HeaderConsistencyResearch\nDisallow: /private\nUser-agent: HeaderConsistencyResearch\nDisallow: /also\n'
        self.assertTrue(allowed(policy, 'https://example.com/public')[0])
        self.assertFalse(allowed(policy, 'https://example.com/private')[0])
        self.assertFalse(allowed(policy, 'https://example.com/also')[0])

    def test_review_preserves_original_eligibility(self):
        from netsec.review import apply_review
        data = {'robots': [{'url': 'https://example.com/robots.txt', 'decision': 'parsed',
                           'body': 'User-agent: *\nDisallow: /private*'}],
                'rows': [{'eligible': True, 'final_url': 'https://example.com/private/page'}]}
        reviewed = apply_review(data)['rows'][0]
        self.assertTrue(reviewed['collector_eligible'])
        self.assertFalse(reviewed['eligible'])
        self.assertTrue(reviewed['review_exclusions'])


if __name__ == '__main__':
    unittest.main()
