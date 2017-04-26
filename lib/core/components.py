import os
import re
import logging


from lib.core.exceptions import NodeMismatchException, MissingFixesException


log = logging.getLogger(__name__)


class Components:

    INCLUDES_PATTERN = re.compile(r'^#include (<|")(.*?)(>|").*$', re.MULTILINE)
    VERSION = 1

    def __init__(self, vcs, repo_path, source_id, max_node=None, extensions=None):
        """
        Class for creating and populating the final component index. This index can be used to generate the machine
        learning data set.
        
        :param vcs: Instance of the appropriate VCS implementation.
        :param repo_path: Path to the repository, should be the same as vcs.repo_path
        :param source_id: The ID of the source (project).
        :param max_node: Latest node to consider for the component index, currently checked out if None.
        :param extensions: File extensions to consider for components, default is ['.cpp', '.c.', '.h'].
        """
        self.vcs = vcs
        self.repo_path = repo_path
        self.max_node = max_node if max_node is not None else vcs.fetch_head_node()
        self.max_node_date = vcs.node_to_date(self.max_node)
        self.extensions = [e.lower() for e in extensions] if extensions is not None else ['.c', '.cpp', '.h']
        self.fixes_added = False
        self.index = {
            'meta': {
                'has_history': False,
                'source_id': source_id,
                'node': self.max_node,
                'version': self.VERSION
            },

            'index': {}
        }

    def create_component_index(self):
        """
        Walks the repository path recursively and collects all files. The files are then combined into components:
        A component consists of all files with matching file names and valid extensions, regardless of the path.
        
        :return: The component index as dictionary.
        """
        log.info('Creating component index for node {}'.format(self.max_node))
        self._assert_node_match()

        components = {}
        for path, dirs, files in os.walk(self.repo_path):
            for filename in files:
                component = self.parse_component_name(filename)
                if component is not None:
                    file_path = (path, filename)
                    if component not in components.keys():
                        components[component] = {
                            'files': [file_path],
                            'includes': {},
                            'fixes': set()
                        }
                    else:
                        components[component]['files'].append(file_path)

        self.index['index'] = components
        return self.index

    def add_vulnerability_fixes(self, file_index):
        """
        Adds the vulnerability fixing nodes from the file index to the component index. This is required for fetching
        the node includes.
        
        :param file_index: The file index with the vulerability fixing nodes.
        :return: The extended component index.
        """
        log.info('Adding fixing nodes to components')

        for node, files in file_index.items():
            node_date = self.vcs.node_to_date(node)
            if self.max_node_date >= node_date:
                log.debug('Node date is valid, including: {} (max {})'.format(node_date, self.max_node_date))
                for f in files:
                    component = self.parse_component_name(f)
                    if component is None:
                        continue
                    if component in self.index['index'].keys():
                        self.index['index'][component]['fixes'].add(node)
                    else:
                        log.warn('Component {} is not in component index'.format(component))

        self.fixes_added = True
        return self.index

    def parse_component_name(self, filename):
        """
        Returns the component name for the given file name.
        
        :param filename: The file name to convert.
        :return: The component name or None if the file extension is invalid.
        """
        name, ext = os.path.splitext(os.path.split(filename)[-1])
        if ext.lower() in self.extensions:
            return name
        return None

    def fetch_includes_fs(self):
        """
        Collects the include statements for each component from the file system and adds the resulting set to the
        component index. Requires an existing component index to extend.
        
        :return: The extended component index.
        """
        log.info('Fetching includes from the file system')
        self._assert_node_match()

        for component, data in self.index['index'].items():
            log.debug('Fetching FS includes for component {}'.format(component))

            includes = set()
            for file_path in data['files']:
                with open(os.path.join(file_path[0], file_path[1]), 'r') as f:
                    includes.update(self._parse_includes(f.read()))
            self.index['index'][component]['includes'][self.max_node] = ('o', includes)

        return self.index

    def _assert_node_match(self):
        current_node = self.vcs.fetch_current_node()
        if self.max_node != current_node:
            log.error('Current node and max_node argument do not match: {} / {}'.format(current_node, self.max_node))
            raise NodeMismatchException('Checked out node and max_node argument do not match!')

    def fetch_includes_node(self):
        """
        Collects and adds the include statements for each component from precursors of nodes that fixed a vulnerability 
        of the component. Requires and existing component index to extend with the fixing nodes added.

        :return: The extended component index.
        """
        log.info('Fetching includes from past nodes')
        if not self.fixes_added:
            log.error('Fixes were not added before fetching the node includes')
            raise MissingFixesException('Fixes were not added before fetching the node includes')

        for component, data in self.index['index'].items():
            files = [os.path.join(f[0], f[1]) for f in data['files']]
            for node in data['fixes']:
                fetch_node = self.vcs.fetch_precursor_node(node)
                log.debug('Fetching includes for component {} in {}'.format(component, node))

                includes = set()
                for content in self.vcs.fetch_node_contents(files, fetch_node):
                    includes.update(self._parse_includes(content))

                if len(includes) > 0:
                    flag = 'o'
                    if includes in [i[1] for i in self.index['index'][component]['includes'].values()]:
                        flag = 'd'
                    log.info('Adding ({}) includes for {} in {}'.format(flag, component, node))
                    self.index['index'][component]['includes'][node] = (flag, includes)
                else:
                    log.error('Got empty include set for {} in {}'.format(component, node))

        self.index['meta']['has_history'] = True

        return self.index

    def _parse_includes(self, content):
        includes = [i[1] for i in self.INCLUDES_PATTERN.findall(content)]
        includes = set([os.path.split(i)[-1] for i in includes])
        return includes