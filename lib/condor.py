import os
import logging
from itertools import chain


from lib.core import serialize
from lib.core.helpers import timeit, read_or_exit
from lib.core.components import Components
from lib.core.dataset import DataSetBuilder
from lib.core.exceptions import NodeMismatchException, SourceMismatchException, MissingHistoryException
from lib.miner import MozillaMiner
from lib.vcs import Hg


log = logging.getLogger(__name__)


class Condor:

    DATA_DIR = 'data'
    NODE_INDEX_FILE = 'node_index.pickle'
    FILE_INDEX_FILE = 'file_index.pickle'

    def __init__(self, source, repo_path):
        """
        Class that provides all functions for the Command Line Interface.
        
        :param source: Source (project) to use, requires an appropriate implementation.
        :param repo_path: Path to the local clone of the repository.
        :param max_node: Which node (commit / changeset) to use as reference. 
        """

        self.source_id = source
        self.save_dir = os.path.join(self.DATA_DIR, self.source_id)

        if self.source_id == 'mozilla':
            self.vcs = Hg(repo_path)
            self.miner = MozillaMiner(self.vcs, self.save_dir)
        else:
            print('ERROR: specified source is not implemented')
            exit(1)

        self.repo_path = repo_path
        self.file_index_path = os.path.join(self.save_dir, self.FILE_INDEX_FILE)

    def print_repo_stats(self):
        head_node = self.vcs.fetch_head_node()
        print('head node:      {} ({})'.format(head_node, self.vcs.node_to_date(head_node)))
        curr_node = self.vcs.fetch_current_node()
        print('current node:   {} ({})'.format(curr_node, self.vcs.node_to_date(curr_node)))

    def print_component_stats(self, read_path):
        index = read_or_exit(read_path)
        meta = index['meta']
        data = index['index']
        print('source:                 {}'.format(meta['source_id']))
        print('node:                   {}'.format(meta['node']))
        print('node date:              {}'.format(self.vcs.node_to_date(meta['node'])))
        print('contains history:       {}'.format(meta['has_history']))
        print('index version:          {}'.format(meta['version']))
        print('')
        print('components:             {}'.format(len(data.keys())))
        print('components vulnerable:  {}'.format(sum(1 if len(c['fixes']) > 0 else 0 for c in data.values())))
        print('vulnerabilities:        {}'.format(sum(len(c['fixes']) for c in data.values())))
        print('distinct includes:      {}'.format(
            len(set(chain.from_iterable(
                [incl[1] for incl in chain.from_iterable([c['includes'].values() for c in data.values()])])))
        ))

    @timeit
    def checkout_head(self):
        print('reverting to head node')
        self.vcs.checkout_head()
        print('done')

    @timeit
    def checkout_node(self, node):
        print('checking out node {}'.format(node))
        self.vcs.checkout_node(node)
        print('done')

    @timeit
    def scrape(self):
        print('scraping advisory pages for {}'.format(self.source_id))
        self.miner.scrape_overview()
        self.miner.scrape_advisories()
        print('done')

    @timeit
    def build_preliminary_indices(self):
        print('creating preliminary indices for {}'.format(self.source_id))
        print('storage path: {}'.format(self.save_dir))
        print('creating node index')
        node_index = self.miner.create_node_index()
        serialize.persist(node_index, os.path.join(self.save_dir, self.NODE_INDEX_FILE))
        print('done')
        print('creating file index')
        file_index = self.miner.create_file_index(node_index)
        serialize.persist(file_index, self.file_index_path)
        print('done')

    @timeit
    def build_component_index(self, save_path, max_node=None, date=None, exclude_history=False):
        if not os.path.exists(self.file_index_path):
            print('ERROR: file index does not yet exist')
            exit(1)

        if max_node is None and date is None:
            print('using head node')
            node = max_node
        else:
            if max_node is not None:
                print('node is set, checking out node {} ({})'.format(max_node, self.vcs.node_to_date(max_node)))
                node = max_node
            else:
                node = self.vcs.date_to_node(date)
                print('date is set, checking out node {} ({})'.format(node, date))
            self.vcs.checkout_node(node)

        components = Components(self.vcs, self.repo_path, self.source_id, max_node=node)

        print('building component index for {}, storing at {}'.format(self.source_id, save_path))
        print('creating raw index from file system')
        try:
            components.create_component_index()
        except NodeMismatchException:
            print('ERROR: specified node and repository state do not match!')
            exit(1)
        print('adding fixing nodes from file index')
        components.add_vulnerability_fixes(serialize.read(self.file_index_path))
        print('fetching includes from file system')
        components.fetch_includes_fs()
        if exclude_history:
            print('not including includes from history')
        else:
            print('fetching includes from history')
            components.fetch_includes_node()
        index = components.index

        serialize.persist(index, save_path)

        if max_node is not None:
            print('reverting to head node')
            self.vcs.checkout_head()
        print('done')

    @timeit
    def build_data_set(self, read_path, save_path, target_type, period):
        print('building data set for component index {}'.format(read_path))
        print('the data set will be saved at {}'.format(save_path))

        is_regression = (target_type == 'r')
        if is_regression:
            print('feature matrix type is regression')
        else:
            print('feature matrix type is classification')

        index = read_or_exit(read_path)
        try:
            builder = DataSetBuilder(self.vcs, index, self.source_id)
        except SourceMismatchException:
            print('ERROR: the specified source and the index source do not match')
            exit(1)

        if period == 'history':
            print('including history in data set')
            try:
                if is_regression:
                    data_set = builder.from_history_regression()
                else:
                    data_set = builder.from_history_classification()
            except MissingHistoryException:
                print('ERROR: there is no revision history in the components data structure')
                exit(1)
        else:
            data_set = builder.from_current(is_regression)

        sparse = builder.to_sparse(data_set)
        serialize.persist(sparse, save_path)
        print('done')
