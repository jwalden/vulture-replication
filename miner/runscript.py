import os
import argparse
import logging
from hglib.error import ServerError

import mozilla_vuln as vuln
import combine


logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename='miner.log',
                    filemode='w')

parser = argparse.ArgumentParser(description='''
Miner for building an index of vulnerability-affected Mozilla components. It
combines the Mozilla Foundation Security Advisories (MFSA) with the commits in
the mozilla-central mercurial repository.
''')
parser.add_argument('--scrape-overview', action='store_true',
                    help='scrape and store the MFSA overview page')
parser.add_argument('--scrape-advisories', action='store_true',
                    help='scrape and store the individual advisory pages')
parser.add_argument('--extract-advisories', action='store_true',
                    help='parse stored advisory pages and store found bug numbers')
parser.add_argument('--build-index', metavar='repopath', type=str,
                    help='build the index for the given repository path and store it')

args = vars(parser.parse_args())

# Options for Mozilla Foundation Security Advisories
scrape_overview = args['scrape_overview']
scrape_advisories = args['scrape_advisories']
extract_and_persist_advisories = args['extract_advisories']

# Options for building the index of vulnerability-related commits
repository_path = args['build_index']
build_and_persist_index = repository_path is not None


if scrape_overview:
    print('scraping and storing MFSA overview')
    vuln.scrape_overview()
    print('done')
    print('')

if scrape_advisories:
    print('scraping and storing individual advisories')
    advisories = vuln.parse_overview()
    vuln.scrape_advisories(advisories)
    print('done')
    print('')

if extract_and_persist_advisories:
    print('extracting and storing bug numbers from advisories')
    bug_numbers = vuln.extract_bugs()
    vuln.persist_bugs(bug_numbers)
    print('done')
    print('')

if build_and_persist_index:
    print('building and storing index of vulnerability-related commits, this'
          ' may take some time')
    bug_numbers = vuln.read_persisted()
    try:
        index = combine.create_index(repository_path, bug_numbers)
    except ServerError:
        print('ERROR: provided path is not a valid mercurial repository')
        exit()
    combine.persist_index(index)
    print('done')

if os.path.exists('data/miner/index.pickle'):
    index = combine.read_index()
    print('The index contains {} vulnerability-related bug numbers. {} of those'
          ' could be assigned to {} commits in the repository.'.format(
            len(index.keys()),
            len(filter(lambda x: len(x) != 0, index.values())),
            sum(len(x) for x in index.values()),
          ))
else:
    print('index does not yet exist, please build it first')
