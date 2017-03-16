import os
import logging
import re


log = logging.getLogger(__name__)


def get_components(repo_path):
    """
    Walks the given repository path recursively and collects all cpp, c and h
    files. The files are then combined to components: Equally-named cpp/c and h
    files are a component, as well as individual files of those types.
    Returns a dict of structure:
    {
        component: {
            'files': [(path, filename), ...],
            'includes': set(),
            'vulncount': 0
        },
        ...
    }
    """
    components = {}
    for path, dirs, files in os.walk(repo_path):
        for filename in files:
            component = component_name(filename)
            if component is not None:
                identifier = (path, filename)
                if component not in components.keys():
                    components[component] = {
                        'files': [identifier],
                        'includes': set(),
                        'vulncount': 0
                    }
                else:
                    components[component]['files'].append(identifier)

    return components


def component_name(filename):
    name, ext = os.path.splitext(filename)
    if ext.lower() in ['.c', '.cpp', '.h']:
        return name
    return None


def get_includes(components):
    """
    Collects the include statements for each component. Requires a dict of
    structure: {component: [(path, file), ...])}
    Returns an extended component dict of structure:
    {
    component: {
        'files': [(path, file), ...],
        'includes': set([import, ...]),
        'vulncount': 0
        },
        ...
    }
    """
    pattern = re.compile(r'^#include (<|")(.*?)(>|").*$', re.MULTILINE)
    extended = components.copy()
    for component, metadata in components.items():
        log.debug('Fetching includes for component {}'.format(component))

        includes = set()
        for identifier in metadata['files']:
            with open(os.path.join(identifier[0], identifier[1]), 'r') as f:
                content = f.read()
                includes.update([m[1] for m in pattern.findall(content)])
        extended[component]['includes'] = includes

    return extended
