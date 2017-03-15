import os
import argparse
import logging
import time
from hglib.error import ServerError

from condor.miner import mozilla_vuln as vuln
from condor.miner import combine
from condor.miner import components
from condor.core import serialize
from condor.core.timer import timeit


ADVISORY_OVERVIEW = 'data/miner/advisories.html'
ADVISORIES_DIR = 'data/miner/advisories/'
BUGS = 'data/miner/bugs.pickle'
COMMIT_INDEX = 'data/miner/commit_index.pickle'
FILE_INDEX = 'data/miner/file_index.pickle'
COMPONENTS = 'data/miner/components.pickle'


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
parser.add_argument('--extract-components', metavar='repopath', type=str,
                    help='extract the c, cpp and h files for the given repository')

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

# Options for building the components and feature matrix
extract_components_path = args['extract_components']
extract_components = extract_components_path is not None


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
        commit_index = combine.create_commit_index(repository_path, bug_numbers)
    except ServerError:
        print('ERROR: provided path is not a valid mercurial repository')
        exit()
    serialize.persist(commit_index, COMMIT_INDEX)
    print('done')
    print('')


if build_file_index:
    print('building file index for the stored commit index')

    try:
        commit_index = serialize.read(COMMIT_INDEX)
    except IOError:
        print('ERROR: missing the commit index')
        exit()


    file_index = combine.create_file_index(file_repo_path, commit_index, FILE_INDEX)
    serialize.persist(file_index, FILE_INDEX)

    print('done. elapsed time is {} seconds'.format(elapsed))
    print('')


if extract_components:
    print('extracting all c, cpp and h files from the repository')
    start = time.time()

    index = components.get_components(extract_components_path)

    elapsed = time.time() - start
    print('done. elapsed time is {} seconds'.format(elapsed))
    no_files = [len(x) for x in index.values()]
    largest = no_files.index(max(no_files))
    print('Found {} components with a total of {} files. The largest component '
          'has {} files ({}):'.format(
              len(index),
              sum(no_files),
              max(no_files),
              index.items()[largest][0]
              ))

    print('extracting include statements for each component')
    start = time.time()

    index = components.get_includes(index)

    elapsed = time.time() - start
    serialize.persist(index, COMPONENTS)
    print('done. elapsed time is {} seconds'.format(elapsed))
    print('')
