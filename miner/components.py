import os
import logging


log = logging.getLogger(__name__)


def get_components(repo_path):
    """
    Walks the given repository path recursively and collects all cpp, c and h
    files. The files are then combined to components. Equally-named cpp/c and h
    files are a component, as well as individual files of any type.
    Returns a dict: {component: (path, file), ...])}
    """
    components = {}
    for path, dirs, files in os.walk(repo_path):
        for fname in files:
            name, ext = os.path.splitext(fname)
            if ext.lower() in ['.c', '.cpp', '.h']:
                identifier = (path, fname)
                if name not in components.keys():
                    components[name] = [identifier]
                else:
                    components[name].append(identifier)
                    if components[name][0] != path:
                        log.debug('Encountered same component with differing '
                            'paths: {}'.format(name))

    return components
