import os


class TreeMap:

    def __init__(self, components, index, repo_path, repo_root):
        self.components = components
        self.index = index
        self.repo_path = repo_path
        self.slice = self.repo_path.index(repo_root)
        self.entries = None

    def save_tm3(self, path):
        """
        Stores the tm3 file at the given path.
        
        :param path: Path to the tm3 file.
        :return: None
        """
        with open(path, 'w') as f:
            f.write('')
        with open(path, 'a') as f:
            for entry in self.entries:
                line = '\t'.join([str(e) for e in entry]) + '\n'
                f.write(line)

    def generate_entries(self):
        """
        Generates the entries for the tm3 file. 
        
        :return: List of entries.
        """
        entries = [['Vulnerabilities', 'Size'], ['INTEGER', 'INTEGER']]
        for node in self.fetch_graph_nodes():
            entry = [node[2], node[3]]
            entry.extend(node[0].rsplit('/'))
            entry.append(node[1])
            entries.append(entry)

        self.entries = entries

    def fetch_graph_nodes(self):
        """
        Fetches all the nodes for the graph from the repository. A node is represented by a tuple:
        ('path', 'component name', int(vulnerabilities), int(component size))
        
        :return: A list of graph nodes. 
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
                        len(self.index[component]['fixes']),
                        sizes[component]
                        )
                    nodes.append(node)

        return nodes

    @staticmethod
    def _fetch_sizes(path, files):
        sizes = {c: 0 for c in set([get_component_name(f) for f in files])}
        for f in files:
            component = self.components.parse_component_name(f)
            if component is not None:
                with open(os.path.join(path, f), 'r') as f:
                    sizes[component] += sum(1 for line in f.read())

        return sizes
