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
parser.add_argument('--stats', metavar='path', type=str,
                    help='Show statistics for the existing data structures.')
parser.add_argument('--diff', metavar='rev', nargs=2, type=int,
                    help='Show the components that had to be fixed for vulnerabilities between two revisions.')
parser.add_argument('-p', '--print', metavar='path', type=str,
                    help='Print a pickled data structure, e.g the commit index or the component index.')
parser.add_argument('-s', '--scrape-complete', action='store_true',
                    help='Scrape and store both the MFSA overview page and the individual MFSA pages.')
parser.add_argument('--scrape-overview', action='store_true',
                    help='Scrape and store the MFSA overview page.')
parser.add_argument('--scrape-advisories', action='store_true',
                    help='Scrape and store the individual advisory pages.')
parser.add_argument('--extract-bugs', action='store_true',
                    help='Parse the stored advisory pages, extract and store bug numbers.')
parser.add_argument('--build-commit-index', action='store_true',
                    help='Build the commit index for the given repository.')
parser.add_argument('--build-file-index', action='store_true',
                    help='Build the file index for the stored commit index and the given repository.')
parser.add_argument('--build-components', metavar='out_path', type=str,
                    help='Build the components for the currently checked out revision and store the index at path.')
parser.add_argument('--build-rev-components', metavar=('out_path', 'rev'), type=str, nargs=2,
                    help='Build the components for the specified revision and store the index at path.')
parser.add_argument('--add-rev-includes', metavar='path', type=str,
                    help='Add the includes from the history of vulnerabile revisions to the specified component index.')
parser.add_argument('--build-dataset', metavar=('in_path', 'type', 'period'), type=str, nargs=3,
                    help='''Build the data set from the specified component index. The type can be "r" for regression or "c" for classification.
                    The period is either "history" or "current", where the resulting matrix will or will not contain the includes from the history
                    of vulnerable revisions.''')
parser.add_argument('-r', '--repo', metavar='path', type=str,
                    help='The path to the mozilla-central mercurial repository. Required for building the commit, file and component indices.')

args = vars(parser.parse_args())

if args['repo'] is None and (args['build_commit_index'] is True
                             or args['build_file_index'] is True
                             or args['build_components']
                             or args['build_rev_components']
                             or args['add_rev_includes']):
    parser.error('repository path argument required: --repo or -r')
    exit(1)


condor = Condor(args['repo'])


if args['stats']:
    condor.print_stats(args['stats'])

if args['diff']:
    revs = args['diff']
    condor.diff(revs[0], revs[1])

if args['print']:
    condor.print_structure(args['print'])

if args['scrape_complete']:
    condor.scrape_mfsa_overview()
    condor.scrape_mfsa_pages()

if args['scrape_overview']:
    condor.scrape_mfsa_overview()

if args['scrape_advisories']:
    condor.scrape_mfsa_pages()

if args['extract_bugs']:
    condor.extract_bugs()

if args['build_commit_index']:
    condor.build_commit_index()

if args['build_file_index']:
    condor.build_file_index()

if args['build_components']:
    condor.extract_components(args['build_components'])

if args['build_rev_components']:
    try:
        rev = int(args['build_rev_components'][1])
    except ValueError:
        print('ERROR: revision must be an integer')
        exit(1)
    condor.extract_components(args['build_rev_components'][0], rev)

if args['add_rev_includes']:
    condor.add_revision_includes(args['add_rev_includes'])

if args['build_dataset']:
    argvars = args['build_dataset']
    if argvars[1] not in ('c', 'r'):
        print('ERROR: type must either be "c" for classification or "r" for regression')
        exit(1)
    if argvars[2] not in ('history', 'current'):
        print('ERROR: period must either be "history" or "current"')
        exit(1)
    condor.build_dataset(argvars[0], argvars[1], argvars[2])
