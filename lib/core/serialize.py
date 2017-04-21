import logging
import cPickle as pickle


log = logging.getLogger(__name__)


def persist(data, path):
    """
    Persists data with cPickle.
    
    :param data: Data to persist, must be picklable.
    :param path: Path where the data should be persisted, incl. file name.
    :return: None
    """
    log.info('Pickling and storing {} data at {}'.format(type(data), path))
    with open(path, 'wb') as f:
        pickle.dump(data, f)


def read(path):
    """
    Reads the pickled data from path.
    
    :param path: File that should be unpickled. 
    :return: Unpickled data.
    """
    log.info('Reading pickled data from {}'.format(path))
    with open(path, 'rb') as f:
        data = pickle.load(f)

    return data
