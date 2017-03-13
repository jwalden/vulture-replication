import hglib


def history_iter(repo_path, revrange=None):
    """
    Generator that yields a tuple of (commit number, node, commit message) for
    a given repository path. Optionally a revision range can be specified.
    """
    client = hglib.open(repo_path)
    log = client.log(revrange=revrange)

    for commit in log:
        yield (commit[0], commit[1], commit[5])


def history(repo_path, revrange=None):
    """
    Returns a list of tuples of (commit number, node, commit message) for a
    given repository path. Optionally a revision range can be specified.
    """
    client = hglib.open(repo_path)
    log = client.log(revrange=revrange)

    history = []
    for commit in log:
        history.append((commit[0], commit[1], commit[5]))

    return history


def files(log):
    client = hglib.open(repo_path)
    return client.status(change=log[0])
