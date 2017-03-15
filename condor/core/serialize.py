import logging
import cPickle as pickle


log = logging.getLogger(__name__)


def persist(data, path):
    """
    Persists data to path with cPickle.
    """
    log.info('Storing pickled {} data at {}'.format(type(data), path))
    with open(path, 'wb') as f:
        pickle.dump(data, f)


def read(path):
    """
    Reads the pickled data from path.
    """
    log.info('Reading pickled data from {}'.format(path))
    data = None
    with open(path, 'rb') as f:
        data = pickle.load(f)
    return data
