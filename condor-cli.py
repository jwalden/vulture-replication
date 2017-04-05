#!/usr/bin/env python

import argparse
import logging


from condor.condor import Condor


logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename='condor.log',
                    filemode='w')

parser = argparse.ArgumentParser(description='''
Tool for building the data set of vulnerability-affected Mozilla components. It
combines the Mozilla Foundation Security Advisories (MFSA) with the commits in
the mozilla-central mercurial repository.

As some of the steps require quite some time, most notably the lookup of
vulnerability-related bug numbers in the individual commit messages, the
creation of the data set is split into several intermediate steps. These
intermediate indices can then be combined into the final data set.
''')
parser.add_argument('--stats', action='store_true',
                    help='show statistics for the existing data structures')
parser.add_argument('-p', '--print', metavar='path', type=str,
                    help='print a pickled data structure, e.g the commit index')
parser.add_argument('-s', '--scrape-complete', action='store_true',
                    help='scrape and store both the MFSA overview page and the individual MFSA pages')
parser.add_argument('--scrape-overview', action='store_true',
                    help='scrape and store the MFSA overview page')
parser.add_argument('--scrape-advisories', action='store_true',
                    help='scrape and store the individual advisory pages')
parser.add_argument('-b', '--build-complete', action='store_true',
                    help='build the complete data set from scratch, except scraping the MFSA`s')
parser.add_argument('--extract-bugs', action='store_true',
                    help='parse stored advisory pages, extract and store bug numbers')
parser.add_argument('--build-commit-index', action='store_true',
                    help='build the commit index for the given repository path and store it')
parser.add_argument('--build-file-index', action='store_true',
                    help='build the file index for the stored commit index and the given repository')
parser.add_argument('--extract-components', action='store_true',
                    help='combine indices and the repository structure into information about components')
parser.add_argument('--add-rev-includes', action='store_true',
                    help='add the includes from vulnerability revisions to the components')
parser.add_argument('--build-dataset', action='store', choices=['current', 'history'],
                    help='build the numpy dataset (feature matrix) from the stored component information')
parser.add_argument('-r', '--repo', metavar='path', type=str,
                    help='the path to the mozilla-central mercurial repository')

args = vars(parser.parse_args())

if args['repo'] is None and (args['build_complete'] is True
                             or args['build_commit_index'] is True
                             or args['build_file_index'] is True
                             or args['extract_components'] is True):
    parser.error('repository path argument required: --repo or -r')
    exit(1)


condor = Condor(args['repo'])

if args['stats']:
    condor.print_stats()

if args['scrape_complete']:
    condor.scrape_mfsa_overview()
    condor.scrape_mfsa_pages()

if args['scrape_overview']:
    condor.scrape_mfsa_overview()

if args['scrape_advisories']:
    condor.scrape_mfsa_pages()

if args['build_complete']:
    print('building complete data set from scratch, without scraping of advisories')
    print('this will take 30+ minutes!')
    condor.extract_bugs()
    condor.build_commit_index()
    condor.build_file_index()
    condor.extract_components()
    condor.add_revision_includes()
    condor.build_dataset()

if args['extract_bugs']:
    condor.extract_bugs()

if args['build_commit_index']:
    condor.build_commit_index()

if args['build_file_index']:
    condor.build_file_index()

if args['extract_components']:
    condor.extract_components()

if args['add_rev_includes']:
    condor.add_revision_includes()

if args['build_dataset'] is not None:
    include_revs = args['build_dataset'] == 'history'
    condor.build_dataset(include_revs)

if args['print'] is not None:
    condor.print_structure(args['print'])
