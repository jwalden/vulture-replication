import hglib
import logging


log = logging.getLogger(__name__)


def history_iter(repo_path, revrange=None):
    """
    Generator that yields a tuple of (commit number, node, commit message) for
    a given repository path. Optionally a revision range can be specified.
    """
    with hglib.open(repo_path) as client:
        log = client.log(revrange=revrange)

        for commit in log:
            yield (commit[0], commit[1], commit[5])


def history(repo_path, revrange=None):
    """
    Returns a list of tuples of (commit number, node, commit message) for a
    given repository path. Optionally a revision range can be specified.
    """
    with hglib.open(repo_path) as client:
        log = client.log(revrange=revrange)

        history = []
        for commit in log:
            history.append((commit[0], commit[1], commit[5]))

    return history


def files(repo_path, commits):
    """
    Returns the changed files for the given repository and commits.
    Commit of structure (commit number, node, message). Returned dict of
    structure {revision: [(code, filename), ...], ...}
    """
    changed = {}
    with hglib.open(repo_path) as client:
        for commit in commits:
            rev = commit[0]
            log.debug('Get changeset for rev {}'.format(rev))
            changed[rev] = client.status(change=rev, modified=True)

    return changed
