import logging
import os.path
import numpy as np

from itertools import chain


log = logging.getLogger(__name__)


def from_current(components):
    """
    Builds the data set from the components data structure where the feature
    matrix only contains the includes from the current revision. Returns a
    tuple: (feature matrix, row names, column names). The last column in the
    feature matrix represents the target, i.e. the vulnerability vector.
    """
    log.info('Building data set from current includes')
    columns = list(set(chain.from_iterable([c['includes'][-1] for c in components.values()])))
    rows = components.keys()
    matrix = np.zeros((len(rows), len(columns) + 1), dtype=np.uint8)
    j_max = len(columns)

    for i, component in enumerate(rows):
        for j, include in enumerate(columns):
            if include in components[component]['includes'][-1]:
                matrix[i, j] = 1
        matrix[i, j_max] = len(components[component]['fixes'])

    return (matrix, rows, columns)


def from_history(components):
    """
    Builds the data set from the components data structure where the feature
    matrix contains the includes from the current revision as well as the
    includes from vulnerability-related revisions. This means that there will
    be more than one entry for some components. Returns a tuple:
    (feature matrix, row names, column names). The last column in the feature
    matrix represents the target, i.e. the vulnerability vector.
    """
    log.info('Building data set from history')
    columns = list(set(chain.from_iterable(chain.from_iterable([c['includes'].values() for c in components.values()]))))
    rows = [c[0] for c in components.items() for i in c[1]['includes'].keys()]
    matrix = np.zeros((len(rows), len(columns) + 1), dtype=np.uint8)
    j_max = len(columns)

    # Fetch the indices of the 1-columns and vulncount for each component
    incl_indices = {c: [] for c in components.keys()}
    for component, data in components.items():
        current_indices = []
        for include in data['includes'][-1]:
            current_indices.append(columns.index(include))
        incl_indices[component].append((len(data['fixes']), current_indices))

        fixes = sorted(list(data['fixes']))
        vulncount = 0
        for fix in fixes:
            if fix in data['includes'].keys():
                fix_indices = []
                for include in data['includes'][fix]:
                    fix_indices.append(columns.index(include))
                incl_indices[component].append((vulncount, fix_indices))

            vulncount += 1

    # Assign the 1 values and vulncount to the previously fetched indices
    for i, component in enumerate(rows):
        vulncount, indices = incl_indices[component].pop()
        for j in indices:
            matrix[i, j] = 1
        matrix[i, j_max] = vulncount

    return (matrix, rows, columns)



def to_sparse(dataset):
    """
    Builds a sparse representation of the data set for persistence.
    Returns a tuple: ([1-coordinates], vulnerability vector, row names,
    column names). The 1-coordinates are tuples of y and x coordinates that
    mark an include (value 1) in the feature matrix.
    """
    ones = np.where(dataset[0] == 1)
    coordinates = zip(ones[0], ones[1])

    return (coordinates, dataset[0][:,-1:], dataset[1], dataset[2])


def from_sparse(sparse):
    """
    Builds the data set from the sparse representation. Returns a tuple:
    (feature matrix, row names, column names). The last column in the
    feature matrix represents the target, i.e. the vulnerability vector.
    """
    rows = sparse[2]
    columns = sparse[3]
    matrix = np.zeros((len(rows), len(columns) + 1), dtype=np.uint8)
    matrix[:,-1:] = sparse[1]
    for i, j in sparse[0]:
        matrix[i, j] = 1

    return (matrix, rows, columns)
