import os
import argparse
import logging
from hglib.error import ServerError

import mozilla_vuln as vuln
import combine
import serialize


ADVISORY_OVERVIEW = 'data/miner/advisories.html'
ADVISORIES_DIR = 'data/miner/advisories/'
BUGS = 'data/miner/bugs.pickle'
COMMIT_INDEX = 'data/miner/index.pickle'
FILE_INDEX = 'data/miner/file_index.pickle'


logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename='miner.log',
                    filemode='w')

parser = argparse.ArgumentParser(description='''
Miner for building an index of vulnerability-affected Mozilla components. It
combines the Mozilla Foundation Security Advisories (MFSA) with the commits in
the mozilla-central mercurial repository.
''')
parser.add_argument('--stats', action='store_true',
                    help='show statistics for the existing indices')
parser.add_argument('--scrape-overview', action='store_true',
                    help='scrape and store the MFSA overview page')
parser.add_argument('--scrape-advisories', action='store_true',
                    help='scrape and store the individual advisory pages')
parser.add_argument('--extract-bugs', action='store_true',
                    help='parse stored advisory pages and store found bug numbers')
parser.add_argument('--build-commit-index', metavar='repopath', type=str,
                    help='build the commit index for the given repository path and store it')
parser.add_argument('--build-file-index', metavar='repopath', type=str,
                    help='build the file index for the stored commit index and the given repository')

args = vars(parser.parse_args())

# General Options
stats = args['stats']

# Options for Mozilla Foundation Security Advisories
scrape_overview = args['scrape_overview']
scrape_advisories = args['scrape_advisories']
extract_and_persist_bugs = args['extract_bugs']

# Options for building the index of vulnerability-related commits
repository_path = args['build_commit_index']
build_and_persist_commit_index = repository_path is not None
file_repo_path = args['build_file_index']
build_file_index = file_repo_path is not None


if scrape_overview:
    print('scraping and storing MFSA overview')
    vuln.scrape_overview(ADVISORY_OVERVIEW)
    print('done')
    print('')

if scrape_advisories:
    print('scraping and storing individual advisories')
    advisories = vuln.parse_overview(ADVISORY_OVERVIEW)
    vuln.scrape_advisories(advisories, ADVISORIES_DIR)
    print('done')
    print('')

if extract_and_persist_bugs:
    print('extracting and storing bug numbers from advisories')
    bug_numbers = vuln.extract_bugs(ADVISORIES_DIR)
    serialize.persist(bug_numbers, BUGS)
    print('done')
    print('')

if build_and_persist_commit_index:
    print('building and storing index of vulnerability-related commits, this'
          ' may take some time')
    try:
        bug_numbers = serialize.read(BUGS)
    except IOError:
        print('ERROR: missing the stored vulnerability bug numbers from advisories, run --extract-advisories')
        exit()
    if bug_numbers is None:
        print('ERROR: could not read the stored vulnerability bug numbers')
        exit()
    try:
        index = combine.create_commit_index(repository_path, bug_numbers)
    except ServerError:
        print('ERROR: provided path is not a valid mercurial repository')
        exit()
    serialize.persist(index, COMMIT_INDEX)
    print('done')
    print('')

if build_file_index:
    print('building file index for the stored commit index')
    try:
        index = serialize.read(COMMIT_INDEX)
    except IOError:
        print('ERROR: missing the commit index')
        exit()
    file_index = combine.create_file_index(file_repo_path, index, FILE_INDEX)
    print('done')
    for bugno, files in file_index.items():
        print('{}: {}'.format(bugno, files))
        print('')

if stats:
    if os.path.exists(COMMIT_INDEX):
        commit_index = serialize.read(COMMIT_INDEX)
        print('The commit index contains {} vulnerability-related bug numbers. {} of'
              ' those could be assigned to {} commits in the repository.'.format(
                len(commit_index.keys()),
                len(filter(lambda x: len(x) != 0, commit_index.values())),
                sum(len(x) for x in commit_index.values()),
              ))
        print('')
    else:
        print('commit index does not yet exist')
        print('')

    if os.path.exists(FILE_INDEX):
        file_index = serialize.read(FILE_INDEX)
        print('The file index contains {} modified files.'.format(
            sum(len(x) for x in file_index.values())
        ))
        print('')
    else:
        print('file index does not yet exist')
        print('')
