import hglib

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


def files(repo_path, commit):
    """
    Returns a list of the changed files for the given repository and commit.
    Commit of structure (commit number, node, message). Returned list of
    structure [(code, filename), ...]
    """

    changed = []
    with hglib.open(repo_path) as client:
        changed = client.status(change=commit[0], modified=True)

    return changed
