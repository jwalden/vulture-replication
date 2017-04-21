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


from lib.miner.miner import Miner


log = logging.getLogger(__name__)


class MozillaMiner(Miner):

    BASE_URL = 'http://www.mozilla.org'
    OVERVIEW_URL = BASE_URL + '/en-US/security/advisories/'
    BUG_PATTERN = re.compile('^(bug_)?id=([0-9,]+)$')

    def __init__(self, hg, save_dir):
        """
        Miner implementation for the Mozilla project.
        
        :param hg: Instance of the mercurial VCS implementation.
        :param save_dir: Path to the storage directory.  
        """
        Miner.__init__(self, hg, save_dir)

        self.overview_path = os.path.join(self.save_path, 'advisory_overview.html')
        self.advisory_path = os.path.join(self.save_path, 'advisories/')
        self._mkdirs(self.advisory_path)

    def scrape_overview(self):
        log.info('Scraping MFSA overview page')
        r = requests.get(self.OVERVIEW_URL, headers=self.HEADERS)
        with open(self.overview_path, 'w') as f:
            f.write(r.content)

    def scrape_advisories(self, ignore_existing=True):
        log.info('Scraping individual MFSA pages')
        advisories = self._parse_overview()
        count = len(advisories)
        for i, advisory in enumerate(advisories):
            mfsa_path = os.path.join(self.advisory_path, advisory[0] + '.html')
            if not ignore_existing or (ignore_existing and not os.path.exists(mfsa_path)):
                log.info('Scraping {} of {}: {}'.format(i, count, advisory[0]))
                r = requests.get(self.BASE_URL + advisory[1],
                                 headers=self.HEADERS)
                with open(mfsa_path, 'w') as f:
                    f.write(r.content)

    def _parse_overview(self):
        """
        Parses the stored MFSA overview page and returns a list tuples (MFSA identifier, Link) pointing to individual
        advisory pages.
        
        :return: List of tuples (MFSA identifier, link) 
        """
        log.info('Parsing stored MFSA overview page (extracting MFSA links)')
        with open(self.overview_path, 'r') as f:
            content = f.read()
        body = self._get_article_body(content)
        ul = body.find_all('ul')

        advisories = []
        for lst in ul:
            for li in lst.find_all('li'):
                a = li.find('a')
                if a is not None:
                    advisories.append((a.find('span').text, a.attrs['href']))

        return advisories

    def create_node_index(self):
        log.info('Creating the node index for the Mozilla Project')
        pattern = re.compile(
            r'([bB](ug)?( |=)#?(?P<bug0>[0-9]{6,}))|(\(.*(?P<bug1>[0-9]{6,}), r=.*\))|^#?(?P<bug2>[0-9]{6,}).*')
        groups = ['bug0', 'bug1', 'bug2']
        bugs = self._extract_bugs()

        index = {bno: [] for bno in bugs}
        log.info('Built unpopulated index with {} vulnerability bug numbers'.format(len(bugs)))
        for node in self.vcs.fetch_log():
            bug_matches = pattern.finditer(node[1])
            for match in bug_matches:
                for group in groups:
                    bugno = match.group(group)
                    if bugno in bugs:
                        log.info('Found node with vulnerabilities: {}'.format(node))
                        index[bugno].append(node[0])

        return index

    def _extract_bugs(self):
        """
        Extracts and returns the bug numbers from all stored MFSA advisory pages.
        
        :return: List of bug numbers as strings.
        """
        log.info('Extracting bug nubmers from MFSA advisories')
        advisories = os.listdir(self.advisory_path)
        count = len(advisories)
        bugs = []
        for i, advisory in enumerate(advisories):
            log.info('Parsing advisory {} of {}'.format(i, count))
            advisorybugs = self._parse_advisory(os.path.join(self.advisory_path, advisory))
            if len(advisorybugs) == 0:
                log.error('No referenced bugs for advisory {}'.format(advisory))
            bugs.extend(advisorybugs)

        return bugs

    def _parse_advisory(self, path):
        """
        Parses a single advisory page and returns the bug numbers.
        
        :param path: Path to the stored advisory page. 
        :return: List of bug numbers as strings.
        """
        with open(path, 'r') as f:
            content = f.read()
        body = self._get_article_body(content)

        bugs = []
        for link in body.find_all('a'):
            href = link.attrs['href']
            query = unquote(urlparse(href).query).replace('\n', '')
            ids = self.BUG_PATTERN.findall(query)
            if len(ids) > 0:
                bugs.extend(ids[0][1].split(','))

        return bugs

    @staticmethod
    def _get_article_body(content):
        bs = BeautifulSoup(content, 'html5lib')
        return bs.find('div', attrs={'itemprop': 'articleBody'})

