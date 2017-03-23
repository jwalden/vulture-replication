import re
import logging
import os

from itertools import chain

import condor.miner.mozilla_hg as hg
from condor.miner.components import component_name


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
            revision: [(flag, file), ...],
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
        file_index[bugno][rev] = files
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
            for code, f in files:
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
