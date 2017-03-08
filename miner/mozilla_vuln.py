import requests
import re
import os
import logging

from bs4 import BeautifulSoup

try:
    from urllib.parse import urlparse, unquote
except ImportError:
    from urlparse import urlparse
    from urllib import unquote


log = logging.getLogger(__name__)
headers = {'user-agent': 'vulture-replication/0.0.1'}
pattern = re.compile('^(bug_)?id=([0-9,]+)$')


def scrape_overview(overview_path='data/miner/advisories.html'):
    """
    Scrapes the advisory overview page and stores it in overview_path.
    """
    r = requests.get('https://www.mozilla.org/en-US/security/advisories/',
        headers=headers)
    with open(overview_path, 'w') as f:
        f.write(r.content)


def parse_overview(overview_path='data/miner/advisories.html'):
    """
    Parses the advisory overview page. Returns a list of tuples of (MFSA, URL).
    """
    content = ''
    with open(overview_path, 'r') as f:
        content = f.read()
    body = _get_article_body(content)
    ul = body.find_all('ul')

    advisories = []
    for lst in ul:
        for li in lst.find_all('li'):
            a = li.find('a')
            if a is not None:
                advisories.append((a.find('span').text, a.attrs['href']))

    return advisories


def scrape_advisories(advisories, path='data/miner/advisories'):
    """
    Scrapes the individual advisory pages and stores them in path. Advisories
    of structure (MFSA, URL).
    """
    count = len(advisories)
    for i, advisory in enumerate(advisories):
        mfsa_path = os.path.join(path, advisory[0] + '.html')
        if not os.path.exists(mfsa_path):
            log.info('Scraping {} of {}: {}'.format(i, count, advisory[0]))
            r = requests.get('http://www.mozilla.org' + advisory[1],
                headers=headers)
            with open(mfsa_path, 'w') as f:
                f.write(r.content)


def parse_advisory(path):
    """
    Returns the bugzilla bug numbers for a given advisory.
    """
    content = ''
    with open(path, 'r') as f:
        content = f.read()
    body = _get_article_body(content)

    bugs = []
    for link in body.find_all('a'):
        href = link.attrs['href']
        query = unquote(urlparse(href).query).replace('\n', '')
        ids = pattern.findall(query)
        if len(ids) > 0:
            bugs.extend(ids[0][1].split(','))

    return bugs


def _get_article_body(content):
    bs = BeautifulSoup(content, 'html5lib')
    return bs.find('div', attrs={'itemprop': 'articleBody'})


def extract_bugs(path='data/miner/advisories'):
    """
    Extracts and returns the bug numbers for all advisories stored in the given
    path.
    """
    advisories = os.listdir(path)
    count = len(advisories)
    bugs = []
    for i, advisory in enumerate(advisories):
        log.info('Parsing {} of {}'.format(i, count))
        advisorybugs = parse_advisory(os.path.join(path, advisory))
        if len(advisorybugs) == 0:
            log.error('No referenced bugs for advisory {}'.format(advisory))
        bugs.extend(advisorybugs)

    return bugs
