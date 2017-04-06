import os


from condor.miner.combine import get_component_name


class TreeMap:

    def __init__(self, components, repo_path, root='mozilla-central'):
        self.components = components
        self.repo_path = repo_path
        self.slice = self.repo_path.index(root)
        self.entries = None

    def save_tm3(self, path):
        with open(path, 'w') as f:
            f.write('')
        with open(path, 'a') as f:
            for entry in self.entries:
                line = '\t'.join([str(e) for e in entry]) + '\n'
                f.write(line)

    def generate_entries(self):
        entries = [['Vulnerabilities', 'Size'], ['INTEGER', 'INTEGER']]
        for node in self.fetch_nodes():
            entry = [node[2], node[3]]
            entry.extend(node[0].rsplit('/'))
            entry.append(node[1])
            entries.append(entry)

        self.entries = entries

    def fetch_nodes(self):
        """
        Fetches the nodes for the repository. A node is represented by a tuple:
        ('path', 'component name', int(vulnerabilities), int(component size))
        """
        nodes = []
        for path, dirs, files in os.walk(self.repo_path):
            sizes = self._fetch_sizes(path, files)
            components = sizes.keys()
            for component in components:
                if component is not None:
                    node = (
                        path[self.slice:],
                        component,
                        len(self.components[component]['fixes']),
                        sizes[component]
                        )
                    nodes.append(node)

        return nodes

    def _fetch_sizes(self, path, files):
        sizes = {c: 0 for c in set([get_component_name(f) for f in files])}
        for f in files:
            component = get_component_name(f)
            if component is not None:
                with open(os.path.join(path, f), 'r') as f:
                    sizes[component] += sum(1 for line in f.read())

        return sizes

if __name__ == '__main__':
    from condor.core import serialize
    from condor.core.config import Config
    treemap = TreeMap(serialize.read(Config().components), '/home/hklauser/school/semester-6/BA/repos/mozilla-central')
    treemap.generate_entries()
    treemap.save_tm3('data/treemap.tm3')
