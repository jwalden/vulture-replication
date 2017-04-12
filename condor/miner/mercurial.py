import hglib
import logging
import os.path

from itertools import chain


log = logging.getLogger(__name__)


class CondorHg:

    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.client = hglib.open(repo_path)

    def __del__(self):
        self.client.close()

    def history_iter(self, revrange=None):
        """
        Generator that yields a tuple of (commit number, node, commit message)
        for a given repository path. If no revision range is specified, a
        generator for the whole history will be returned.
        """
        log = self.client.log(revrange=revrange)

        for commit in log:
            yield (int(commit[0]), commit[1], commit[5])

    def history(self, revrange=None):
        """
        Returns a list of tuples of (commit number, node, commit message) for a
        given repository path. If no revision range is specified, the whole
        history will be returned.
        """
        log = self.client.log(revrange=revrange)

        history = []
        for commit in log:
            history.append((int(commit[0]), commit[1], commit[5]))

        return history

    def mod_files(self, commits):
        """
        Returns the changed files for the given repository and commits.
        Commits of structure [(commit number, node, message), ...]. Returns dict
        of structure {revision: [(code, filename), ...], ...}
        """
        changed = {}
        for commit in commits:
            rev = commit[0]
            log.debug('Get changeset for rev {}'.format(rev))
            changed[rev] = self.client.status(change=rev, modified=True)

        return changed

    def rev_file_contents(self, files, revision):
        """
        Generator that yields the content of the specified files for the given
        revision.
        """
        for f in files:
            try:
                yield self.client.cat(files=[f], rev=revision)
            except hglib.error.CommandError:
                continue

    def checkout_rev(self, revision):
        """
        Checks out the specified revision of the repository.
        """
        log.info('Checking out revision {}'.format(revision))

        self.client.update(rev=revision, clean=True)
        log.debug('Client state: {}'.format(self.client.identify()))

    def checkout_head(self):
        """
        Checks out the head revision of the repository.
        """
        log.info('Checking out head revision')

        self.client.update(clean=True)
        log.debug('Client state: {}'.format(self.client.identify()))

    def current_revision(self):
        """
        Returns the currently checked out revision number.
        """
        return self.client.identify(num=True)

    def rev_date(self, revision):
        """
        Returns the datetime of a revision.
        """
        revision = self.current_revision() if revision is None else revision
        return self.client.log(revrange=revision)[0][6]

    def date_to_rev(self, date):
        """
        Returns the last revision number for a given date.
        """
        return self.client.log(date=date)[0][0]
