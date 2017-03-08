import hglib


def history_iter(repo_path, revrange=None):
    """
    Generator that yields a tuple of (node, commit message, affected files) for
    a given repository path. Optionally a revision range can be specified.
    """
    client = hglib.open(repo_path)
    log = client.log(revrange=revrange)

    for commit in log:
        yield (commit[1], commit[5], client.status(change=commit[0]))
