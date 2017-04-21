import time
import logging
import datetime
from functools import wraps
from pprint import pprint


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
