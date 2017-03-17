import logging
import os.path
import numpy as np

from itertools import chain


log = logging.getLogger(__name__)


def from_components(components):
    columns = list(set(chain.from_iterable([c['includes'] for c in components.values()])))
    rows = components.keys()
    dataset = np.zeros((len(rows), len(columns) + 1), dtype=np.uint8)
    j_max = len(columns)

    for i, component in enumerate(rows):
        for j, include in enumerate(columns):
            if include in components.get(component)['includes']:
                dataset[i, j] = 1
        dataset[i, j_max] = components.get(component)['vulncount']

    return dataset
