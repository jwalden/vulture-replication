import os.path
import numpy as np
import datetime
from pprint import pprint
from hglib.error import ServerError, CommandError
from itertools import chain

from core.config import Config
from core import serialize
from core.timer import timeit
from miner.combine import Combiner
from miner import dataset
from miner.mercurial import CondorHg
import miner.mozilla_mfsa as mfsa


class Condor:

    def __init__(self, repo_path=None):
        self.config = Config()
        self.hg = None if repo_path is None else CondorHg(repo_path)
        self.combiner = Combiner(self.hg)

    def print_stats(self, components_path):
        print('-- VULNERABILITY BUG LIST --')
        if os.path.exists(self.config.bugs):
            bugs = serialize.read(self.config.bugs)
            print('{} vulnerability-related bug numbers total'.format(len(bugs)))
            print('{} distinct vulnerability-related bug numbers'.format(
                len(set(bugs))
            ))
        else:
            print('the list of bugs has not yet been extracted from the advisories')
        print('')

        print('-- COMMIT INDEX --')
        if os.path.exists(self.config.commit_index):
            commit_index = serialize.read(self.config.commit_index)
            print('{} vulnerability-related bug numbers'.format(
                len(commit_index.keys())
            ))
            print('{} bug numbers assigned to {} commits'.format(
                len(filter(lambda x: len(x) != 0, commit_index.values())),
                sum(len(x) for x in commit_index.values())
            ))
        else:
            print('the commit index does not yet exist')
        print('')

        print('-- FILE INDEX --')
        if os.path.exists(self.config.file_index):
            file_index = serialize.read(self.config.file_index)
            print('{} revisions in regards to {} vulnerability-related bugs'.format(
                sum(len(x) for x in file_index.values()),
                len(file_index.keys())
            ))
            print('{} files flagged as modified'.format(
                len(list(chain.from_iterable(chain.from_iterable([x.values() for x in file_index.values()]))))
            ))
        else:
            print('file index does not yet exist')
        print('')

        print('-- COMPONENTS --')
        components = self._read(components_path)
        print('{} components with {} files'.format(
            len(components.keys()),
            sum(len(x['files']) for x in components.values())
        ))
        print('{} distinct current includes'.format(
            len(set(chain.from_iterable([c['includes'][-1][1] for c in components.values()])))
        ))
        print('{} distinct includes with revisions'.format(
            len(set(chain.from_iterable([incl[1] for incl in chain.from_iterable([c['includes'].values() for c in components.values()])])))
        ))
        print('{} components flagged as vulnerable'.format(
            sum(1 if len(x['fixes']) > 0 else 0 for x in components.values()),
        ))
        print('{} vulnerability counts in total'.format(
            sum(len(x['fixes']) for x in components.values())
        ))
        print('')

        print('-- DATA SET --')
        if os.path.exists(self.config.dataset):
            matrix = dataset.from_sparse(serialize.read(self.config.dataset))[0]
            print('the shape of the feature matrix is {}'.format(matrix.shape))
            nonzero = np.count_nonzero(matrix[:,-1])
            print('{} rows with vulnerabilities ({} %)'.format(
                nonzero,
                100 * (float(nonzero) / matrix.shape[0])
            ))
        else:
            print('the feature matrix has not yet been built')

    def diff(self, rev1, rev2):
        file_index = self._read(self.config.file_index)
        for component in sorted(list(self.combiner.get_diff(file_index, rev1, rev2))):
            print(component)

    def print_structure(self, path):
        pprint(self._read(path), width=140)

    @timeit
    def scrape_mfsa_overview(self):
        print('scraping and storing MFSA overview')
        mfsa.scrape_overview(self.config.mfsa_overview)
        print('done')

    @timeit
    def scrape_mfsa_pages(self):
        print('scraping and storing individual advisories')
        advisories = mfsa.parse_overview(self.config.mfsa_overview)
        mfsa.scrape_advisories(advisories, self.config.mfsa_dir)
        print('done')

    @timeit
    def extract_bugs(self):
        print('extracting and storing bug numbers from advisories')
        bug_numbers = mfsa.extract_bugs(self.config.mfsa_dir)
        serialize.persist(bug_numbers, self.config.bugs)
        print('done')

    @timeit
    def build_commit_index(self):
        print('building and storing index of vulnerability-related commits, this'
              ' may take some time')
        try:
            bug_numbers = serialize.read(self.config.bugs)
        except IOError:
            print('ERROR: missing the stored vulnerability bug numbers from advisories, run --extract-advisories')
            exit(1)
        if bug_numbers is None:
            print('ERROR: could not read the stored vulnerability bug numbers')
            exit(1)
        try:
            commit_index = self.combiner.create_commit_index(bug_numbers)
        except ServerError:
            print('ERROR: provided path is not a valid mercurial repository')
            exit(1)
        serialize.persist(commit_index, self.config.commit_index)
        print('done')

    @timeit
    def build_file_index(self):
        print('building file index for the stored commit index')

        try:
            commit_index = serialize.read(self.config.commit_index)
        except IOError:
            print('ERROR: missing the commit index')
            exit(1)

        file_index = self.combiner.create_file_index(commit_index)
        serialize.persist(file_index, self.config.file_index)

    @timeit
    def extract_components(self, out_path, revision=None, date=None):
        if not os.path.exists(self.config.file_index):
            print('ERROR: file index does not yet exist')
            exit(1)

        print('building components and storing at {}'.format(out_path))
        print('extracting all c, cpp and h files from the repository')
        if revision is None and date is None:
            print('using most recent revision')
        else:
            if revision is not None:
                rev = revision
                print('extracting components for revision {} ({})'.format(
                    rev, self.combiner.hg.rev_date(revision)))
            else:
                print('extracting components for date {}, fetching revision'.format(date))
                rev = self.hg.date_to_rev(date)
                print('latest revision of {} is {}'.format(date, rev))

            self.combiner.revision = rev

            try:
                print('checking out revision {}'.format(rev))
                self.hg.checkout_rev(rev)
            except CommandError:
                print('ERROR: invalid revision {}'.format(revision))
                exit(1)

        index = self.combiner.create_components()

        print('done')
        no_files = [len(x['files']) for x in index.values()]
        largest = no_files.index(max(no_files))
        print('found {} components with a total of {} files. The largest component '
              'has {} files ({})'.format(
                  len(index),
                  sum(no_files),
                  max(no_files),
                  index.items()[largest][0]
                  ))

        print('extracting include statements for each component')
        index = self.combiner.get_includes_fs(index)

        print('assigning vulnerability fix revisions to each component')
        file_index = serialize.read(self.config.file_index)
        index = self.combiner.label_components(file_index, index)
        serialize.persist(index, out_path)

        if revision is not None or date is not None:
            print('reverting to head revision')
            self.hg.checkout_head()
        print('done')

    @timeit
    def add_revision_includes(self, path):
        print('extracting and adding revision includes to the existing components'
              ' at {}'.format(path))
        print('this will take some time')

        components = self._read(path)
        components = self.combiner.get_includes_rev(components)
        serialize.persist(components, path)

        print('done')

    @timeit
    def build_dataset(self, path, target_type, period):
        print('building data set for components at {}'.format(path))

        is_regression = target_type == 'r'
        if is_regression:
            print('feature matrix type is regression')
        else:
            print('feature matrix type is classification')

        components = self._read(path)

        if period == 'history':
            print('including history in data set')
            if max(len(c['includes']) for c in components.values()) == 1:
                print('ERROR: there does not seem to be a revision history in the components data structure')
                print('run with --add-rev-history first if you want to build the history data set')
                exit(1)
            feature_matrix = dataset.from_history(components, is_regression)
        else:
            print('from current revision only')
            feature_matrix = dataset.from_current(components, is_regression)

        sparse = dataset.to_sparse(feature_matrix)
        serialize.persist(sparse, self.config.dataset)

        print('done')

    @timeit
    def build_semiannual(self, dir_path):
        if not os.path.exists(self.config.file_index):
            print('ERROR: file index does not yet exist')
            exit(1)

        print('building the matrices for the complete history, this will take a long time')
        print('storing results in {}'.format(dir_path))
        indices_path = os.path.join(dir_path, 'indices')
        if not os.path.exists(indices_path):
            os.makedirs(indices_path)
        else:
            if not os.path.isdir(dir_path):
                print('ERROR: not a directory: {}'.format(dir_path))
                exit(1)

        self.hg.checkout_head()

        first_date = self.hg.rev_date(0)
        last_date = self.hg.rev_date(self.hg.current_revision())

        print('first date: {}, last date: {}'.format(first_date, last_date))
        dates = self._get_datepairs(first_date, last_date)
        print('building {} matrices in total'.format(4 * len(dates)))

        i, i_max = 1, len(dates)
        for pair in dates:
            for j, date in enumerate(pair):
                rev = self.hg.date_to_rev(date)
                while rev is None:
                    print('{} has no rev'.format(date))
                    date = date + datetime.timedelta(days=1)
                    rev = self.hg.date_to_rev(date)

                if j == 0:
                    print('building training matrix')
                    prefix = '{}_train_{}_'.format(i, date)
                else:
                    print('building test matrix')
                    prefix = '{}_test_{}_'.format(i, date)
                reg_path = os.path.join(dir_path, prefix + 'reg.pickle')
                cla_path = os.path.join(dir_path, prefix + 'cla.pickle')
                components_path = os.path.join(indices_path, '{}.pickle'.format(
                    date
                ))

                print('building matrices {} of {} (date: {}, rev: {})'.format(
                    i, i_max, date, rev
                ))
                self.combiner.revision = rev
                self.hg.checkout_rev(rev)
                self._build_matrices(components_path, reg_path, cla_path)

            print('')
            i += 1


        self.hg.checkout_head()
        print('done')

    def _get_datepairs(self, first_date, last_date):
        train_delta = datetime.timedelta(days=91)
        test_delta = datetime.timedelta(days=182)

        dates = [(first_date, first_date + test_delta)]
        while True:
            next_train = dates[-1][0] + train_delta
            next_test = next_train + test_delta

            if next_train >= last_date or next_test > last_date:
                break
            else:
                dates.append((next_train, next_test))

        return dates

    def _build_matrices(self, components_path, reg_path, cla_path):
        if os.path.exists(components_path):
            components = serialize.read(components_path)
        else:
            print('creating components')
            components = self.combiner.create_components()
            print('getting includes')
            components = self.combiner.get_includes_fs(components)
            print('labelling components')
            file_index = serialize.read(self.config.file_index)
            components = self.combiner.label_components(file_index, components)
            print('getting revision includes')
            components = self.combiner.get_includes_rev(components)
            print('storing components')
            serialize.persist(components, components_path)

        if not os.path.exists(reg_path):
            print('building and storing regression matrix')
            data = dataset.to_sparse(
                dataset.from_history(components, is_regression=True))
            serialize.persist(data, reg_path)

        if not os.path.exists(cla_path):
            print('building classification matrix')
            data = dataset.to_sparse(
                dataset.from_history(components, is_regression=False))
            serialize.persist(data, cla_path)


    def _read(self, path):
        try:
            data = serialize.read(path)
        except IOError:
            print('ERROR: File does not exist or is invalid: {}'.format(path))
            exit(1)

        return data
