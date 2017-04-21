import os
import errno
import logging

from itertools import chain


log = logging.getLogger(__name__)


class Miner(object):

    HEADERS = {'user-agent': 'vulture-replication/0.1.0'}
    OVERVIEW_FILE = 'overview.html'

    def __init__(self, vcs, save_dir):
        """
        Abstract class for the implementation of mining for different sources.
        
        :param vcs: The VCS client for interfacing with the repository.
        :param save_dir: Path to the storage directory. 
        """
        self.vcs = vcs
        self.save_path = save_dir
        self._mkdirs(save_dir)

    @staticmethod
    def _mkdirs(path):
        log.info('Creating directories in chain: {}'.format(path))
        try:
            os.makedirs(path)
        except OSError as e:
            if e.errno == errno.EEXIST and os.path.isdir(path):
                log.debug('Directories already exist')
                pass
            else:
                raise

    def scrape_overview(self):
        """
        Scrape and store the advisory overview.
        
        :return: None
        """
        raise NotImplementedError

    def scrape_advisories(self, ignore_existing=True):
        """
        Scrape and store the individual advisories.
        
        :param ignore_existing: Whether to ignore already scraped advisories.
        :return: None
        """
        raise NotImplementedError

    def create_node_index(self):
        """
        Create and return the node index. It maps vulnerability identifiers to nodes (e.g. commits or changesets).
        
        :return: The node index dictionary.
        """
        raise NotImplementedError

    def create_file_index(self, node_index):
        """
        Create and return the file index. It maps nodes to lists of modified files.

        :param node_index: The node index.
        :return: The file index dictionary. 
        """
        log.info('Creating file index, VCS type is {}'.format(type(self.vcs)))
        nodes = set(chain.from_iterable(node_index.values()))
        return self.vcs.fetch_modified_files(nodes)
