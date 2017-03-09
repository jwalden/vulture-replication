import re
import cPickle as pickle
import logging

import mozilla_hg as hg


log = logging.getLogger(__name__)


def create_index(repo_path, bugs):
    """
    Combines the vulnerability bug numbers with individual commits. Returns an
    index as dict of {bugno: [(commit number, node, commit message), ...]}.
    """
    pattern = re.compile('([bB](ug)?( |=)#?(?P<bug0>[0-9]{6,}))|(\(.*(?P<bug1>[0-9]{6,}), r=.*\))|^#?(?P<bug2>[0-9]{6}).*')
    groups = ['bug0', 'bug1', 'bug2']
    history = hg.history_iter(repo_path)

    index = {bno: [] for bno in bugs}
    log.info('Built raw index with {} vulnerability bug numbers'.format(len(bugs)))
    for commit in history:
        bug_matches = pattern.finditer(commit[2])
        for match in bug_matches:
            for group in groups:
                bugno = match.group(group)
                if bugno in bugs:
                    log.debug('Found vulnerable commit: {}'.format(commit))
                    index[bugno].append(commit)

    return index


def persist_index(index, path='data/miner/index.pickle'):
    with open(path, 'wb') as f:
        pickle.dump(index, f)


def read_index(path='data/miner/index.pickle'):
    index = None
    with open(path, 'rb') as f:
        index = pickle.load(f)
    return index
