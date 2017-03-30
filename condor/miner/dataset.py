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
    columns = list(set(chain.from_iterable([c['includes'][0] for c in components.values()])))
    rows = components.keys()
    matrix = np.zeros((len(rows), len(columns) + 1), dtype=np.uint8)
    j_max = len(columns)

    for i, component in enumerate(rows):
        for j, include in enumerate(columns):
            if include in components[component]['includes'][0]:
                matrix[i, j] = 1
        matrix[i, j_max] = components[component]['vulncount']

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
    columns = list(set(chain.from_iterable(chain.from_iterable([c['includes'] for c in components.values()]))))
    rows = [c[0] for c in components.items() for i in c[1]['includes']]
    matrix = np.zeros((len(rows), len(columns) + 1), dtype=np.uint8)
    j_max = len(columns)

    for i, component in enumerate(rows):
        for j, include in enumerate(columns):
            for includes in components[component]['includes']:
                if include in includes:
                    matrix[i, j] = 1
                matrix[i, j_max] = components[component]['vulncount']

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
