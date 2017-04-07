import re
import logging
import os

from itertools import chain


log = logging.getLogger(__name__)


class Combiner:

    def __init__(self, condor_hg, revision=None):
        self.revision = revision
        self.hg = condor_hg

    def create_commit_index(self, bugs):
        """
        Combines the vulnerability bug numbers with individual commits. Returns an
        index as dict of {bugno: [(commit number, node, commit message), ...]}
        """
        pattern = re.compile(r'([bB](ug)?( |=)#?(?P<bug0>[0-9]{6,}))|(\(.*(?P<bug1>[0-9]{6,}), r=.*\))|^#?(?P<bug2>[0-9]{6,}).*')
        groups = ['bug0', 'bug1', 'bug2']

        index = {bno: [] for bno in bugs}
        log.info('Built unpopulated index with {} vulnerability bug numbers'.format(len(bugs)))
        for commit in self.hg.history_iter():
            bug_matches = pattern.finditer(commit[2])
            for match in bug_matches:
                for group in groups:
                    bugno = match.group(group)
                    if bugno in bugs:
                        log.info('Found vulnerable commit: {}'.format(commit))
                        index[bugno].append(commit)

        return index

    def create_file_index(self, commit_index):
        """
        Creates the file index for the given commit index. The file index contains
        the list of modified files for each bug number and revision as dict:
        {
            bugno: {
                revision: [file, ...],
                ...
            },
            ...
        }
        """
        rev_index = self._create_rev_index(commit_index)
        commits = chain.from_iterable(commit_index.values())
        changed = self.hg.mod_files(commits)

        file_index = {k: {} for k in commit_index.keys()}
        for rev, files in changed.items():
            bugno = rev_index[rev]
            file_index[bugno][rev] = [f[1] for f in files]
            log.debug('Adding revision {} to bug #{}. Files: {}'.format(
                rev, bugno, files))

        return file_index

    def  _create_rev_index(self, commit_index):
        """
        Returns an index that maps each revision number in the given commit index
        to its bug number.
        """
        rev_index = {}
        for bugno, commits in commit_index.items():
            for commit in commits:
                rev_index[commit[0]] = bugno
        return rev_index

    def create_components(self):
        """
        Walks the given repository path recursively and collects all cpp, c and h
        files. The files are then combined to components: Equally-named cpp/c and h
        files are a component, as well as individual files of those types.
        Returns a dict of structure:
        {
            component: {
                'files': [(path, filename), ...],
                'includes': {},
                'fixes': set()
            },
            ...
        }
        """

        log.info('Creating components for revision {} ({})'.format(
            self.revision, self.hg.rev_date(self.revision)))

        components = {}
        for path, dirs, files in os.walk(self.hg.repo_path):
            for filename in files:
                component = get_component_name(filename)
                if component is not None:
                    identifier = (path, filename)
                    if component not in components.keys():
                        components[component] = {
                            'files': [identifier],
                            'includes': {},
                            'fixes': set()
                        }
                    else:
                        components[component]['files'].append(identifier)

        return components

    def get_includes_fs(self, components):
        """
        Collects the include statements for each component from the file system and
        adds the resulting set to the list of includes. Requires an existing
        component dict to extend. Returns a copy of the provided component dict.
        """
        extended = components.copy()
        for component, metadata in components.items():
            log.debug('Fetching includes for component {} from the file system'.format(component))

            includes = set()
            for identifier in metadata['files']:
                with open(os.path.join(identifier[0], identifier[1]), 'r') as f:
                    includes.update(self._includes(f.read()))
            extended[component]['includes'][-1] = includes

        return extended

    def get_includes_rev(self, components, keep_duplicates=False):
        """
        Collects the include statements for each component from vulnerability-
        related revisions and adds the resulting set to the list of includes.
        Requires an existing component dict to extend. Returns a copy of the
        provided component dict.
        """
        log.info('Fetching includes from past revisions')
        if len(max(components.values(), key=lambda x: len(x['fixes']))['fixes']) == 0:
            log.error('Components must be labeled before fetching the revision includes')
            raise ValueError('Components must be labeled before fetching the revision includes')

        extended = components.copy()
        for component, data in extended.items():
            files = [os.path.join(f[0], f[1]) for f in data['files']]
            for rev in data['fixes']:
                fetchrev = int(rev) - 1
                log.debug('Fetching includes for component {} from revision {}'.format(component, fetchrev))

                includes = set()
                for content in self.hg.rev_file_contents(files, fetchrev):
                    includes.update(self._includes(content))
                if keep_duplicates or (includes not in extended[component]['includes'].values()):
                    if len(includes) > 0:
                        log.info('Adding new includes for component {} and revision {}'.format(component, fetchrev))
                        extended[component]['includes'][rev] = includes
                    else:
                        log.error('Got empty include set for {} and revision {}'.format(component, fetchrev))

        return extended

    def _includes(self, content):
        pattern = re.compile(r'^#include (<|")(.*?)(>|").*$', re.MULTILINE)
        includes = [i[1] for i in pattern.findall(content)]
        includes = set([os.path.split(i)[-1] for i in includes])
        return includes

    def label_components(self, file_index, components):
        """
        Combines the file index with the component data structure and adds the
        vulnerability fixing revision numbers to the set. Returns a new
        component data structure with sets of fixing revision numbers.
        """
        log.info('Adding fix revision numbers to components')
        if self.revision is None:
            log.info('Revision is not specified, consider entire vulnerability history')
        else:
            log.info('Revision is set, only include vulnerable revisions up to {}'.format(self.revision))

        labeled = components.copy()
        for revisions in file_index.values():
            for rev, files in revisions.items():
                if self.revision is None or self.revision >= rev:
                    for f in files:
                        component = get_component_name(f)
                        if component in labeled.keys():
                            labeled[component]['fixes'].add(rev)

        return labeled

    def get_diff(self, file_index, rev1, rev2):
        """
        Returns the set of fixed components between two revisions.
        """
        if rev1 > rev2:
            tmp = rev1
            rev1 = rev2
            rev2 = tmp

        rev_files = self._create_rev_files(file_index)
        mod_files = []
        for rev, files in rev_files.items():
            if rev >= rev1 and rev <= rev2:
                mod_files.extend(files)

        mod_files = set([get_component_name(f) for f in mod_files])
        if None in mod_files:
            mod_files.remove(None)

        return mod_files

    def _create_rev_files(self, file_index):
        rev_files = {}
        for rev_dict in file_index.values():
            for rev, files in rev_dict.items():
                if rev in rev_files.keys():
                    rev_files[rev].extend(files)
                else:
                    rev_files[rev] = files

        return rev_files


def get_component_name(filename):
    name, ext = os.path.splitext(os.path.split(filename)[-1])
    if ext.lower() in ['.c', '.cpp', '.h']:
        return name
    return None
