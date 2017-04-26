import hglib
import logging


from lib.vcs.vcs import VCS


log = logging.getLogger(__name__)


class Hg(VCS):

    def __init__(self, repo_path):
        VCS.__init__(self, repo_path)
        self.repo = hglib.open(repo_path)

    def fetch_log(self):
        history = self.repo.log()

        repo_log = []
        for entry in history:
            repo_log.append((entry[1], entry[5]))

        return repo_log

    def fetch_modified_files(self, nodes):
        modified = {}
        for node in nodes:
            files = self.repo.status(change=node, modified=True)
            # hglib.status returns a tuple (flag, filename), only add filenames
            modified[node] = [f[1] for f in files]

        return modified

    def fetch_head_node(self):
        return self.repo.log(limit=1)[0][1]

    def fetch_current_node(self):
        return self.repo.log('.')[0][1]

    def fetch_precursor_node(self, node):
        # TODO: This is probably not entirely correct, as the preceding revision number could be from a later date!!
        revnumber = int(self.repo.log(revrange=node)[0][0])
        return self.repo.log(revrange=revnumber - 1)[0][1]

    def fetch_node_contents(self, files, node):
        for f in files:
            try:
                yield self.repo.cat(files=[f], rev=node)
            except hglib.error.CommandError:
                log.warn('hglib Command Error: File {} missing in node {}'.format(f, node))
                continue

    def checkout_head(self):
        log.info('Checking out head revision')

        self.repo.update(clean=True)
        log.debug('Client state: {}'.format(self.repo.identify()))

    def checkout_node(self, node):
        log.info('Checking out node {}'.format(node))

        self.repo.update(rev=node, clean=True)
        log.debug('Client state: {}'.format(self.repo.identify()))

    def node_to_date(self, node):
        return self.repo.log(revrange=node)[0][6].date()

    def date_to_node(self, date):
        nodes = self.repo.log(date=date)
        if len(nodes) > 0:
            return nodes[0][1]
        return None

    def sort_nodes_asc(self, nodes):
        rev_numbers = []
        for node in nodes:
            # TODO: Sort by date instead of local scope revision number?
            number = int(self.repo.log(revrange=node)[0][0])
            rev_numbers.append((number, node))
        rev_numbers = sorted(rev_numbers, key=lambda x: x[0])

        return [node for number, node in rev_numbers]
