import time
import logging
import datetime
import os
import numpy as np
from functools import wraps
from pprint import pprint
from itertools import chain


from lib.core import serialize
from lib.core.exceptions import InvalidDateException


log = logging.getLogger(__name__)


def timeit(func):
    """
    Decorator function for timing another function. Will print the elapsed time after the execution of func has
    completed.
    
    :param func: Function to decorate 
    :return: Wrapped function 
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()

        ret = func(*args, **kwargs)

        elapsed = time.time() - start
        print('elapsed time: {} seconds'.format(elapsed))
        log.debug('Elapsed time for {}: {} seconds'.format(func.__name__, elapsed))

        return ret

    return wrapper


def print_structure(file_path):
    """
    Pretty print a pickled data structure.
    
    :param file_path: Path to the pickled file to print. 
    :return: None
    """
    pprint(read_or_exit(file_path), width=140)


def read_or_exit(file_path):
    """
    Read the pickled file or exit if it is invalid.
    
    :param file_path: Path to the pickled file to read.
    :return: Contents of the pickled file.
    """
    try:
        data = serialize.read(file_path)
        return data
    except IOError:
        print('ERROR: File does not exist or is invalid: {}'.format(file_path))
        exit(1)


def parse_date(datestring):
    """
    Parse the passed string in YYYY-MM-DD format and return a datetime.Date object.
    
    :param datestring: String in YYYY-MM-DD format.
    :return: datetime.date
    """
    y, m, d = datestring.split('-')
    if len(y) != 4 or len(m) != 2 or len(d) != 2:
        raise InvalidDateException('Date must be of format YYYY-MM-DD')
    return datetime.date(int(y), int(m), int(d))


def count_files(root_dir, extensions):
    """
    Recursively counts the files with the given extensions. 
    
    :param root_dir: Path to the directory to start the search from.
    :param extensions: Extensions to consider for the count. Every extension must have a leading dot and be lower case.
    :return: File count.
    """
    log.info('Counting files in {}'.format(root_dir))
    count = 0
    for path, dirs, files in os.walk(root_dir):
        for filename in files:
            name, ext = os.path.splitext(os.path.split(filename)[-1])
            if ext.lower() in extensions:
                count += 1

    log.info('Found {} files with extensions {}'.format(count, extensions))
    return count


def print_features(dataset, component):
    """
    Print the features of a component in the dataset.
    
    :param dataset: The dataset to get the features from. 
    :param component: The component to print the features for.
    :return: None
    """
    i = dataset[1].index(component)
    while True:
        print('Vulnerabilities: {}'.format(dataset[0][i, -1]))
        for f in np.where(dataset[0][i, :-1] == 1)[0].tolist():
            print(dataset[2][f])
        print('')
        i += 1
        if dataset[1][i] != component:
            break


def print_feature_stats(components):
    includes_c = list(
        chain.from_iterable(c['includes'][components['meta']['node']][1] for c in components['index'].values()))
    includes_h = list(chain.from_iterable(
        i[1] for i in chain.from_iterable([c['includes'].values() for c in components['index'].values()])))
    calls_c = list(chain.from_iterable(c['calls'][components['meta']['node']][1] for c in components['index'].values()))
    calls_h = list(chain.from_iterable(
        i[1] for i in chain.from_iterable([c['calls'].values() for c in components['index'].values()])))
    conditionals_c = list(
        chain.from_iterable(c['conditionals'][components['meta']['node']][1] for c in components['index'].values()))
    conditionals_h = list(chain.from_iterable(
        i[1] for i in chain.from_iterable([c['conditionals'].values() for c in components['index'].values()])))
    defines_c = list(
        chain.from_iterable(c['defines'][components['meta']['node']][1] for c in components['index'].values()))
    defines_h = list(chain.from_iterable(
        i[1] for i in chain.from_iterable([c['defines'].values() for c in components['index'].values()])))
    namespaces_c = list(
        chain.from_iterable(c['namespaces'][components['meta']['node']][1] for c in components['index'].values()))
    namespaces_h = list(chain.from_iterable(
        i[1] for i in chain.from_iterable([c['namespaces'].values() for c in components['index'].values()])))
    print('-- current state:')
    print('includes: {:>21} ({})'.format(len(includes_c), len(set(includes_c))))
    print('function calls: {:>15} ({})'.format(len(calls_c), len(set(calls_c))))
    print('conditionals: {:>17} ({})'.format(len(conditionals_c), len(set(conditionals_c))))
    print('defines: {:>22} ({})'.format(len(defines_c), len(set(defines_c))))
    print('namespaces: {:>19} ({})'.format(len(namespaces_c), len(set(namespaces_c))))
    print('')
    print('-- with feature history:')
    print('includes: {:>21} ({})'.format(len(includes_h), len(set(includes_h))))
    print('function calls: {:>15} ({})'.format(len(calls_h), len(set(calls_h))))
    print('conditionals: {:>17} ({})'.format(len(conditionals_h), len(set(conditionals_h))))
    print('defines: {:>22} ({})'.format(len(defines_h), len(set(defines_h))))
    print('namespaces: {:>19} ({})'.format(len(namespaces_h), len(set(namespaces_h))))