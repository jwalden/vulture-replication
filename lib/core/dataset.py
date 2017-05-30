import numpy as np
import logging
from itertools import chain


from lib.core.exceptions import SourceMismatchException, MissingHistoryException


log = logging.getLogger(__name__)


class DataSetBuilder:

    def __init__(self, vcs, index, source_id):
        """
        Class for creating the machine learning data set from a component index.
        
        :param vcs: Instance of the appropriate VCS implementation.
        :param index: The component index.
        :param source_id: The ID of the source (project).
        """
        self.vcs = vcs
        self.index = index
        self.max_node = self.index['meta']['node']

        if self.index['meta']['source_id'] != source_id:
            raise SourceMismatchException('specified source and index source do not match')

    def from_current(self, feature='includes', is_regression=True):
        """
        Builds the data set from the includes for which the component index was built, excluding ones from earlier
        nodes. The last column in the feature matrix represents the target vector.
        
        :param feature: Dictionary key of the feature to use for the matrix.
        :param is_regression: Regression matrix if True, classification otherwise.
        :return: A tuple: (feature matrix, list of row names, list of column names)
        """
        log.info('Building data set from the most recent node in the component index')
        log.debug('Creating columns, rows and empty matrix')
        columns = list(set(chain.from_iterable([c[feature][self.max_node][1] for c in self.index['index'].values()])))
        rows = self.index['index'].keys()
        matrix = np.zeros((len(rows), len(columns) + 1), dtype=np.uint8)

        log.debug('Populating matrix with include and target values')
        for i, component in enumerate(rows):
            for j, include in enumerate(columns):
                if include in self.index['index'][component][feature][self.max_node][1]:
                    matrix[i, j] = 1
            if is_regression:
                matrix[i, -1] = len(self.index['index'][component]['bugs'].keys())
            else:
                matrix[i, -1] = 1 if len(self.index['index'][component]['bugs'].keys()) > 0 else 0

        return matrix, rows, columns

    def from_history_classification(self, feature='includes'):
        """
        Builds the classification data set with includes from earlier nodes. The last column in the feature matrix
        represents the target vector.
        
        :return: A tuple: (feature matrix, list of row names, list of column names)
        """
        log.info('Building classification data set from history')
        self._assert_history()

        log.debug('Creating columns, rows and empty matrix')
        # Columns: Create a set of all features of all components, convert it to a list so it is ordered
        columns = list(set(chain.from_iterable(
            [incl[1] for incl in chain.from_iterable([c[feature].values() for c in self.index['index'].values()])])))
        # Rows: Repeat the component name for each include set of the component
        rows = [c[0] for c in self.index['index'].items() for i in c[1][feature].keys() if
                c[1][feature][i][0] == 'o']
        matrix = np.zeros((len(rows), len(columns) + 1), dtype=np.uint8)

        log.debug('Fetching matrix indices for each include set of each component')
        indices = {component: [] for component in self.index['index'].keys()}
        for component, data in self.index['index'].items():
            for node, features in data[feature].items():
                if features[0] == 'o':
                    component_indices = []
                    for f in features[1]:
                        component_indices.append(columns.index(f))
                    target = 0
                    if node != self.max_node:
                        target = 1
                    else:
                        '''
                        This is a hack from late in the project that needs refactoring:
                        The max_node is considered an "original" node and will be included in the data set with a
                        target value of 0. But if the same feature set as for the max_node existed in a vulnerable node,
                        it should still have a target value of 1, since it is known that this feature set is vulnerable.
                        This is either the case if there is only one feature set (the one of max_node) and the component
                        has had at least one vulnerability, or if the same feature set is in a vulnerable node
                        considered a duplicate (which isn't included in the matrix).
                        Checking the generated matrices has shown that this hack is correct and that indeed no duplicate
                        feature sets per component are included.
                        '''
                        for bugnode in chain.from_iterable(data['bugs'].values()):
                            if len(data[feature].keys()) == 1 or (bugnode in data[feature].keys() and
                                    data[feature][bugnode][1] == data[feature][self.max_node][1]):
                                target = 1
                                break

                    indices[component].append((target, component_indices))

        matrix = self.__assign_index_values(indices, rows, matrix)

        return matrix, rows, columns

    def from_history_regression(self, feature='includes'):
        """
        Builds the regression data set with includes from earlier nodes. The last column in the feature matrix
        represents the target vector.
        
        :return: A tuple: (feature matrix, list of row names, list of column names)
        """
        log.info('Building regression data set from history')
        self._assert_history()

        log.debug('Creating columns, rows and empty matrix')
        # Columns: Create a set of all features of all components, convert it to a list so it is ordered
        columns = list(set(chain.from_iterable(
            [incl[1] for incl in chain.from_iterable([c[feature].values() for c in self.index['index'].values()])])))
        # Rows: Repeat the component name for each _distinct_ include set of the component (omit duplicates)
        rows = [c[0] for c in self.index['index'].items() for i in c[1][feature].keys() if
                c[1][feature][i][0] == 'o']
        matrix = np.zeros((len(rows), len(columns) + 1), dtype=np.uint8)

        log.debug('Fetching matrix indices for each include set of each component')
        indices = {component: [] for component in self.index['index'].keys()}
        for component, data in self.index['index'].items():
            component_indices = []
            for include in data[feature][self.max_node][1]:
                component_indices.append(columns.index(include))
            vuln_count = len(data['bugs'].keys())
            indices[component].append((vuln_count, component_indices))

            fix_nodes = self.vcs.sort_nodes_asc(chain.from_iterable(data['bugs'].values()))
            if len(fix_nodes) > 0:
                node_bugs = {}
                for bug, nodes in data['bugs'].items():
                    for node in nodes:
                        node_bugs[node] = bug

                encountered_bugs = [node_bugs[fix_nodes[0]]]
                vuln_count = 0
                for node in fix_nodes:
                    if node in data[feature].keys() and data[feature][node][0] == 'o':
                        component_indices = []
                        for include in data[feature][node][1]:
                            component_indices.append(columns.index(include))
                        indices[component].append((vuln_count, component_indices))

                    if not node_bugs[node] in encountered_bugs:
                        vuln_count += 1
                        encountered_bugs.append(node_bugs[node])

        matrix = self.__assign_index_values(indices, rows, matrix)

        return matrix, rows, columns

    def _assert_history(self):
        if not self.index['meta']['has_history']:
            raise MissingHistoryException('the specified index does not contain a history')

    @staticmethod
    def __assign_index_values(indices, rows, matrix):
        log.debug('Assigning matrix values at previously fetched indices')
        for i, component in enumerate(rows):
            try:
                target, component_indices = indices[component].pop()
            except IndexError:
                print('{}: {}'.format(component, indices[component]))
                raise
            for j in component_indices:
                matrix[i, j] = 1
            matrix[i, -1] = target

        return matrix

    @staticmethod
    def to_sparse(data_set):
        """
        Creates a sparse representation of the specified data set. For the feature matrix, only the indices of the
        1-values  in the matrix will be saved. The target vector, row names and column names won't be affected by the
        conversion.
        
        :param data_set: The data set tuple to convert. 
        :return: Picklable sparse representation of the data set.
        """
        ones = np.where(data_set[0] == 1)
        coordinates = zip(ones[0], ones[1])

        return coordinates, data_set[0][:, -1:], data_set[1], data_set[2]

    @staticmethod
    def from_sparse(sparse):
        """
        Builds the data set from its sparse representation.
        
        :param sparse: The sparse representation of the data set. 
        :return: A tuple: (feature matrix, list of row names, list of column names)
        """
        rows = sparse[2]
        columns = sparse[3]
        matrix = np.zeros((len(rows), len(columns) + 1), dtype=np.uint8)
        for i, j in sparse[0]:
            matrix[i, j] = 1
        matrix[:, -1:] = sparse[1]

        return matrix, rows, columns
