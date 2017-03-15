import os
import logging
import re


log = logging.getLogger(__name__)


def get_components(repo_path):
    """
    Walks the given repository path recursively and collects all cpp, c and h
    files. The files are then combined to components. Equally-named cpp/c and h
    files are a component, as well as individual files of any type.
    Returns a dict of structure: {component: [(path, file), ...])}
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


def get_includes(components):
    """
    Collects the include statements for each component. Requires a dict of
    structure: {component: [(path, file), ...])}
    Returns an extended component dict of structure:
    {
    component: {
        'files': [(path, file), ...],
        'includes': set([import, ...])
        }, ...
    }
    """
    pattern = re.compile(r'^#include (<|")(.*?)(>|").*$', re.MULTILINE)
    extended = {}
    for component, files in components.items():
        log.debug('Fetching includes for component {}'.format(component))

        includes = set()
        for identifier in files:
            with open(os.path.join(identifier[0], identifier[1]), 'r') as f:
                content = f.read()
                includes.update([m[1] for m in pattern.findall(content)])
        extended[component] = {
            'files': files,
            'includes': includes
        }

    return extended
