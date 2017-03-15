import re
import logging

import condor.miner.mozilla_hg as hg


log = logging.getLogger(__name__)


def create_commit_index(repo_path, bugs):
    """
    Combines the vulnerability bug numbers with individual commits. Returns an
    index as dict of {bugno: [(commit number, node, commit message), ...]}
    """
    pattern = re.compile('([bB](ug)?( |=)#?(?P<bug0>[0-9]{6,}))|(\(.*(?P<bug1>[0-9]{6,}), r=.*\))|^#?(?P<bug2>[0-9]{6,}).*')
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


def create_file_index(repo_path, commit_index, path):
    """
    Creates the file index for the given commit index. The file index contains
    the modified files for each bug number as dict: {bugno: [(flag, file), ...]}
    """
    file_index = {}
    for bugno, commits in commit_index.items():
        if len(commits) > 0:
            file_index[bugno] = []
            for commit in commits:
                files = hg.files(repo_path, commit)
                file_index[bugno].extend(files)
                log.debug('Adding changes for bug #{}: {}'.format(bugno, files))

    return file_index
