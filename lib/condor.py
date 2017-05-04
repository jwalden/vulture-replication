import os
import logging
import datetime
from itertools import chain


from lib.core import serialize
from lib.core.helpers import timeit, read_or_exit, count_files
from lib.core.components import Components
from lib.core.dataset import DataSetBuilder
from lib.core.exceptions import NodeMismatchException, SourceMismatchException, MissingHistoryException
from lib.core.treemap import TreeMap
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
        self.healthy_nodes = {}

    def print_repo_stats(self):
        """
        Print some statistics about the repository.
        
        :return: None 
        """
        head_node = self.vcs.fetch_head_node()
        print('head node:      {} ({})'.format(head_node, self.vcs.node_to_date(head_node)))
        curr_node = self.vcs.fetch_current_node()
        print('current node:   {} ({})'.format(curr_node, self.vcs.node_to_date(curr_node)))

    def print_component_stats(self, read_path):
        """
        Print stats about the specified component index.
        
        :param read_path: Path to a persisted component index.  
        :return: None
        """
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
        """
        Check out the head (most recent) node of the repository.
        
        :return: None 
        """
        print('reverting to head node')
        self.vcs.checkout_head()
        print('done')

    @timeit
    def checkout_node(self, node):
        """
        Check out the specified node of the repository.
        
        :param node: Node to check out. 
        :return: None
        """
        print('checking out node {}'.format(node))
        self.vcs.checkout_node(node)
        print('done')

    @timeit
    def generate_treemap(self, read_path, save_path):
        """
        Generates the treemap for the given component index and stores it in tm3 format.
        
        :param read_path: The path to the component index to use.
        :param save_path: The path to store the treemap at.
        :param root_dir: The name of the root directory of the repository.
        :return: None
        """
        print('generating treemap for {}'.format(read_path))
        index = read_or_exit(read_path)
        if self.vcs.fetch_current_node() != index['meta']['node']:
            print('reverting repository to component index node: {}'.format(index['meta']['node']))
            self.vcs.checkout_node(index['meta']['node'])
        treemap = TreeMap(index, self.repo_path)
        treemap.generate_entries()

        path = save_path
        if not path.endswith('.tm3'):
            path += '.tm3'
        treemap.save_tm3(path)

        if self.vcs.fetch_current_node() != self.vcs.fetch_head_node():
            print('reverting repository to head node')
            self.vcs.checkout_head()

    @timeit
    def scrape(self):
        """
        Scrape and store the security advisories.
        
        :return: None 
        """
        print('scraping advisory pages for {}'.format(self.source_id))
        self.miner.scrape_overview()
        self.miner.scrape_advisories()
        print('done')

    @timeit
    def build_preliminary_indices(self):
        """
        Build the source specific preliminary indices.
        
        :return: None 
        """
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
        """
        Build the component index.
        
        :param save_path: Path to store the index at. 
        :param max_node: Node for which to build the index, later nodes won't be considered. 
        :param date: Only if max_node is None. Date for which to build the index, later nodes won't be considered.
        :param exclude_history: Whether to exclude the include history.
        :return: None
        """
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
        """
        Build the machine learning data set.
        
        :param read_path: Path to the component index for building the data set. 
        :param save_path: Path to store the data set at.
        :param target_type: Either 'r' for regression or 'c' for classification.
        :param period: Either 'history' for consideration of history includes or 'current'.
        :return: None
        """
        print('building data set from component index {}'.format(read_path))
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

    @timeit
    def build_semiannual(self, save_dir, health_count=6000):
        """
        Build all regression and classification data sets for the entire repository history. It will build a training
        and a validation data set ca. half a year apart, two training data sets are ca. a quarter year apart.
        
        :param save_dir: The directory to save the indices and data sets in.
        :param health_count: How many files a node must have to build the component index.
        :return: None
        """
        print('building semiannual matrices from component index')
        print('the data sets will be saved at {}'.format(save_dir))

        file_index = read_or_exit(self.file_index_path)
        first_date = self.vcs.node_to_date(0)
        last_date = self.vcs.node_to_date(self.vcs.fetch_head_node())

        print('period: {} - {}'.format(first_date, last_date))
        sorted_dates = sorted(list(set(chain.from_iterable(self._get_date_pairs(first_date, last_date)))))
        i_max = len(sorted_dates)
        print('building {} component indices in total ({} data sets)'.format(i_max, 2*i_max))
        for i, matrix_date in enumerate(sorted_dates):
            print('date {} of {} - searching for healthy node in vicinity of {}'.format(i+1, i_max, matrix_date))
            if matrix_date in self.healthy_nodes.keys():
                date, node = self.healthy_nodes[matrix_date]
            else:
                healthy = self._fetch_healthy_node(matrix_date, health_count)
                if healthy is None:
                    print('ERROR: Could not find healthy node in vicinity of {}'.format(matrix_date))
                    continue
                date, node = healthy
            if self.vcs.fetch_current_node() != node:
                self.vcs.checkout_node(node)

            print('building component index for date {} ({})'.format(date, matrix_date))
            components_path = os.path.join(save_dir, 'components_{}.pickle'.format(date))
            regression_path = os.path.join(save_dir, 'matrix_regression_{}.pickle'.format(date))
            classification_path = os.path.join(save_dir, 'matrix_classification_{}.pickle'.format(date))

            if not os.path.exists(components_path):
                components = Components(self.vcs, self.repo_path, self.source_id, max_node=node)
                components.create_component_index()
                components.add_vulnerability_fixes(file_index)
                components.fetch_includes_fs()
                components.fetch_includes_node()
                serialize.persist(components.index, components_path)
                components_index = components.index
            else:
                print('index already exists, using existing one')
                components_index = serialize.read(components_path)

            builder = DataSetBuilder(self.vcs, components_index, self.source_id)
            print('building regression data set')
            if not os.path.exists(regression_path):
                data_set = builder.to_sparse(builder.from_history_regression())
                serialize.persist(data_set, regression_path)

            print('building classification data set')
            if not os.path.exists(classification_path):
                data_set = builder.to_sparse(builder.from_history_classification())
                serialize.persist(data_set, classification_path)
            print('')

    @staticmethod
    def _get_date_pairs(first_date, last_date):
        """
        Generate and return the date pairs for the generation of the semiannual data sets.
        
        :param first_date: Date of the first training data set. 
        :param last_date: Date of the last validation data set.
        :return: A list of date pairs as tuples.
        """
        train_delta = datetime.timedelta(days=91)
        val_delta = datetime.timedelta(days=182)

        dates = [(first_date, first_date + val_delta)]
        while True:
            next_train = dates[-1][0] + train_delta
            next_val = next_train + val_delta

            if next_train >= last_date or next_val > last_date:
                break
            dates.append((next_train, next_val))

        return dates

    def _fetch_healthy_node(self, date, health_count, delta=1, max_delta=15, extensions=Components.DEFAULT_EXT):
        """
        Searches and checks out a healthy node in vicinity of the specified date. A healthy node consists of at least
        health_count files with the correct extensions.
        
        :param date: Date to search a healthy node for.
        :param health_count: Required file count to be considered a healthy node.
        :param delta: Number of days to jump in one step.
        :param max_delta: Maximum days to jump back or forth for the search.
        :param extensions: The extensions to consider for the file count.
        :return: Date of the healthy node or None
        """
        log.info('Searching for a healthy node in the vicinity of {}'.format(date))
        if date in self.healthy_nodes.keys():
            log.info('Healthy node for date {} already encountered'.format(date))
            return self.healthy_nodes[date]

        i, current_date = 0, date
        while i <= (max_delta * 2):
            if i != 1:
                # Skip i == 1 as it would be the same as i == 0
                if i % 2 == 0:
                    current_date = date + datetime.timedelta(days=(i/2) * delta)
                else:
                    current_date = date - datetime.timedelta(days=(i/2) * delta)
                log.debug('Current date: {}'.format(current_date))

                node = self.vcs.date_to_node(current_date)
                if node is not None:
                    self.vcs.checkout_node(node)
                    count = count_files(self.repo_path, extensions)
                    if count >= health_count:
                        log.info('Found healthy node at {}: {}'.format(current_date, node))
                        if current_date != date:
                            self.healthy_nodes[date] = current_date, node
                        return current_date, node

            i += 1
