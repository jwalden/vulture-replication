import os


class TreeMap:

    def __init__(self, index, repo_path):
        """
        Class for generating a treemap.
        
        :param index: The component index to use.
        :param repo_path: Path to the repository.
        :param root_dir: Name of the root folder of the repository (e.g. mozilla-central).
        """
        self.index = index
        self.repo_path = repo_path
        self.slice = repo_path.index(self._get_root_dir(repo_path))
        self.entries = None

    @staticmethod
    def _get_root_dir(repo_path):
        root_dir = os.path.split(repo_path)
        if root_dir[-1] == '':
            root_dir = os.path.split(root_dir[0])

        return root_dir[-1]

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
                        len(self.index['index'][component]['bugs'].keys()),
                        sizes[component]
                        )
                    nodes.append(node)

        return nodes

    def _fetch_sizes(self, path, files):
        sizes = {c: 0 for c in set([self.parse_component_name(f) for f in files])}
        for f in files:
            component = self.parse_component_name(f)
            if component is not None:
                with open(os.path.join(path, f), 'r') as f:
                    sizes[component] += sum(1 for line in f.read())

        return sizes

    @staticmethod
    def parse_component_name(filename):
        """
        Returns the component name for the given file name.

        :param filename: The file name to convert.
        :return: The component name or None if the file extension is invalid.
        """
        name, ext = os.path.splitext(os.path.split(filename)[-1])
        if ext.lower() in ['.c', '.cpp', '.h']:
            return name
        return None
