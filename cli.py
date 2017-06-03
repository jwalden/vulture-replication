#!/usr/bin/env python

import argparse
import logging


from lib.core import helpers
from lib.core.exceptions import InvalidDateException
from lib.condor import Condor


logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename='condor.log',
                    filemode='w')

parser = argparse.ArgumentParser(description='''
Tool for building the data set of vulnerability-affected components. It combines security advisories with commits in the
software repository.

The building of the preliminary indices (node index and file index) is source specific. An appropriate implementation
of the project to be mined has to exist. A local copy of the software repository is required as well.

The generation of the component index and the final data set is project independent, but requires the preliminary
indices.
''')

general = parser.add_argument_group('general', 'general helper functions')
general.add_argument('--repo-stats', action='store_true',
                     help='print statistics about the repository')
general.add_argument('--component-stats', metavar='read_path',
                     help='print statistics about the component index at read_path')
general.add_argument('--checkout-head', action='store_true',
                     help='check out the head node of the appropriate repository')
general.add_argument('--checkout', metavar='node',
                     help='check out the specified node of the appropriate repository')
general.add_argument('--treemap', metavar=('read_path', 'save_path'), type=str, nargs=2,
                     help='generate a treemap for the component index at read_path and save it in tm3 format at '
                          'save_path.')
general.add_argument('-p', '--print', metavar='path', type=str,
                     help='pretty print a pickled data structure')
general.add_argument('--path-replace', metavar='index_path', type=str,
                     help='replace the repository root path in the specified component index')

mining = parser.add_argument_group('mining', 'arguments for source specific mining')
mining.add_argument('--scrape', action='store_true',
                    help='scrape and store non-existent advisories')
mining.add_argument('--build-prelim', action='store_true',
                    help='build the preliminary indices (node index and file index)')

components = parser.add_argument_group('components', 'arguments for creation of the component index')
components.add_argument('--build-components', metavar='save_path', type=str,
                        help='build the components for the currently checked out node')
components.add_argument('--build-node-components', metavar=('save_path', 'node'), type=str, nargs=2,
                        help='build the components for the specified node and store the index at save_path')
components.add_argument('--build-date-components', metavar=('save_path', 'date'), type=str, nargs=2,
                        help='build the components for the specified YYYY-MM-DD date and store the index at save_path')
components.add_argument('--exclude-history', action='store_true',
                        help='''if this flag is set, the includes from past nodes will not be fetched. this speeds up
                        the creation of the component index significantly, but will render the creation of the history
                        data set impossible''')

dataset = parser.add_argument_group('dataset', 'arguments for building the machine learning dataset from the component '
                                               'index')
dataset.add_argument('--build-dataset', metavar=('read_path', 'save_path', 'type', 'period'), type=str, nargs=4,
                     help='''build the data set from the component index at read_path and save it at save_path. the type
                          can be either "r" for regression or "c" for classification. the period is either "history" or
                          "current", where the resulting matrix will or will not contain the includes from the history
                          of vulnerable nodes.''')
dataset.add_argument('--build-semiannual', metavar='save_dir', type=str, nargs=1,
                     help='''build semiannual component indices and history matrices for the entire repository history
                     ''')

flags = parser.add_argument_group('flags', 'flags required for most other arguments')
flags.add_argument('-s', '--source', type=str, choices=('mozilla', 'aosp'),
                   help='source (project) to use')
flags.add_argument('-r', '--repo', metavar='path', type=str,
                   help='path to the local repository clone of the specified source')
flags.add_argument('-f', '--feature', choices=('includes', 'calls', 'conditionals', 'defines', 'namespaces'),
                   help='the feature to use for building the data set, \'includes\' by default')


args = vars(parser.parse_args())


if args['print']:
    helpers.print_structure(args['print'])
    exit(0)

if args['repo'] is None or args['source'] is None:
    print('ERROR: Please make sure that both the source and repo arguments are set')
    exit(1)

condor = Condor(args['source'], args['repo'])

if args['repo_stats']:
    condor.print_repo_stats()

if args['component_stats']:
    condor.print_component_stats(args['component_stats'])

if args['checkout_head']:
    condor.checkout_head()

if args['checkout']:
    condor.checkout_node(args['checkout'])

if args['treemap']:
    condor.generate_treemap(args['treemap'][0], args['treemap'][1])

if args['path_replace']:
    condor.path_replace(args['path_replace'])

if args['scrape']:
    condor.scrape()

if args['build_prelim']:
    condor.build_preliminary_indices()

if args['build_components']:
    condor.build_component_index(args['build_components'], exclude_history=args['exclude_history'])

if args['build_node_components']:
    argvars = args['build_node_components']
    condor.build_component_index(argvars[0], max_node=argvars[1], exclude_history=args['exclude_history'])

if args['build_date_components']:
    argvars = args['build_date_components']
    try:
        date = helpers.parse_date(argvars[1])
    except (InvalidDateException, ValueError):
        print('ERROR: date must be of format YYYY-MM-DD')
        exit(1)
    condor.build_component_index(argvars[0], date=date, exclude_history=args['exclude_history'])

if args['build_dataset']:
    argvars = args['build_dataset']
    feature = args['feature'] if args['feature'] is not None else 'includes'
    condor.build_data_set(argvars[0], argvars[1], argvars[2], argvars[3], feature)

if args['build_semiannual']:
    argvars = args['build_semiannual']
    condor.build_semiannual(argvars[0])