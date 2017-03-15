import time

from functools import wraps


def timeit(func):
    """
    Decorator function for timing another function. Will print the elapsed time
    after the execution of func has completed.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()

        ret = func(*args, **kwargs)

        elapsed = time.time() - start
        print('elapsed time: {} seconds'.format(elapsed))

        return ret
    
    return wrapper
