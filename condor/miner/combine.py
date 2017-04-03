import re
import logging
import os

from itertools import chain

import condor.miner.mozilla_hg as hg


log = logging.getLogger(__name__)


def create_commit_index(repo_path, bugs):
    """
    Combines the vulnerability bug numbers with individual commits. Returns an
    index as dict of {bugno: [(commit number, node, commit message), ...]}
    """
    pattern = re.compile(r'([bB](ug)?( |=)#?(?P<bug0>[0-9]{6,}))|(\(.*(?P<bug1>[0-9]{6,}), r=.*\))|^#?(?P<bug2>[0-9]{6,}).*')
    groups = ['bug0', 'bug1', 'bug2']
    history = hg.history_iter(repo_path)

    index = {bno: [] for bno in bugs}
    log.info('Built unpopulated index with {} vulnerability bug numbers'.format(len(bugs)))
    for commit in history:
        bug_matches = pattern.finditer(commit[2])
        for match in bug_matches:
            for group in groups:
                bugno = match.group(group)
                if bugno in bugs:
                    log.info('Found vulnerable commit: {}'.format(commit))
                    index[bugno].append(commit)

    return index


def create_file_index(repo_path, commit_index):
    """
    Creates the file index for the given commit index. The file index contains
    the list of modified files for each bug number and revision as dict:
    {
        bugno: {
            revision: [file, ...],
            ...
        },
        ...
    }
    """
    rev_index = _create_rev_index(commit_index)
    commits = chain.from_iterable(commit_index.values())
    changed = hg.files(repo_path, commits)

    file_index = {k: {} for k in commit_index.keys()}
    for rev, files in changed.items():
        bugno = rev_index[rev]
        file_index[bugno][rev] = [f[1] for f in files]
        log.debug('Adding revision {} to bug #{}. Files: {}'.format(
            rev, bugno, files))

    return file_index


def  _create_rev_index(commit_index):
    """
    Returns an index that maps each revision number in the given commit index
    to its bug number.
    """
    rev_index = {}
    for bugno, commits in commit_index.items():
        for commit in commits:
            rev_index[commit[0]] = bugno
    return rev_index


def create_components(repo_path):
    """
    Walks the given repository path recursively and collects all cpp, c and h
    files. The files are then combined to components: Equally-named cpp/c and h
    files are a component, as well as individual files of those types.
    Returns a dict of structure:
    {
        component: {
            'files': [(path, filename), ...],
            'includes': [],
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
                        'includes': [],
                        'vulncount': 0
                    }
                else:
                    components[component]['files'].append(identifier)

    return components


def get_includes_fs(components):
    """
    Collects the include statements for each component from the file system and
    adds the resulting set to the list of includes. Requires an existing
    component dict to extend. Returns a copy of the provided component dict.
    """
    extended = components.copy()
    for component, metadata in components.items():
        log.debug('Fetching includes for component {} from the file system'.format(component))

        includes = set()
        for identifier in metadata['files']:
            with open(os.path.join(identifier[0], identifier[1]), 'r') as f:
                includes.update(_includes(f.read()))
        extended[component]['includes'].append(includes)

    return extended


def get_includes_rev(repo_path, components, file_index):
    """
    Collects the include statements for each component from vulnerability-
    related revisions and adds the resulting set to the list of includes.
    Requires an existing component dict to extend. Returns a copy of the
    provided component dict.
    """
    log.info('Fetching includes from past revisions')
    component_keys = components.keys()
    component_revs = []
    for revisions in file_index.values():
        for rev, files in revisions.items():
            for f in files:
                component = component_name(os.path.split(f)[-1])
                if component in component_keys:
                    component_revs.append((component, rev))
    component_revs = set(component_revs)

    i, i_max = 0, len(component_revs)
    extended = components.copy()
    for component, rev in component_revs:
        i += 1
        fetchrev = int(rev) - 1
        log.debug('{}/{} Fetching includes for component {} from revision {}'.format(i, i_max, component, fetchrev))
        files = [os.path.join(f[0], f[1]) for f in components[component]['files']]
        includes = set()
        for content in hg.rev_file_contents(repo_path, files, fetchrev):
            includes.update(_includes(content))
        if includes not in extended[component]['includes']:
            log.info('Found differing includes for component {} and revision {}'.format(component, fetchrev))
            extended[component]['includes'].append(includes)

    return extended


def _includes(content):
    pattern = re.compile(r'^#include (<|")(.*?)(>|").*$', re.MULTILINE)
    includes = [i[1] for i in pattern.findall(content)]
    includes = set([os.path.split(i)[-1] for i in includes])
    return includes


def label_components(file_index, components):
    """
    Combines the file index with the component data structure and flags
    componets as vulnerable. Returns a new component data structure with
    updated vulnerability counts.
    """
    nokey = []
    total = 0
    labeled = components.copy()
    for revisions in file_index.values():
        # Store already encountered components per bug number (only count once):
        encountered = []
        for files in revisions.values():
            for f in files:
                cname = component_name(os.path.split(f)[-1])
                if cname is not None and cname not in encountered:
                    encountered.append(cname)
                    try:
                        labeled[cname]['vulncount'] += 1
                        total += 1
                    except KeyError:
                        nokey.append(cname)
                        log.exception('Component not in component index: {}'.format(
                            cname
                        ))
    log.debug('{} component vulnerabilities in total, {} could not be assigned (deleted?): {}'.format(total, len(nokey), nokey))

    return labeled


def component_name(filename):
    name, ext = os.path.splitext(filename)
    if ext.lower() in ['.c', '.cpp', '.h']:
        return name
    return None
