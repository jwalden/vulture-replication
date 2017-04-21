

class VCS(object):

    def __init__(self, repo_path):
        """
        Abstract class for the implementation of different VCS clients.
        
        :param repo_path: Path to the repository. 
        """
        self.repo_path = repo_path
        self.repo = None

    def fetch_log(self):
        """
        Fetches and returns the repository history as a list of tuples of (node, node message). The log includes
        the entire history, regardless of which node is currently checked out.
        
        :return: List of tuples: (node, node_message)
        """
        raise NotImplementedError

    def fetch_modified_files(self, nodes):
        """
        Fetches and returns the changed files for the given nodes.
        
        :param nodes: Iterable of nodes. 
        :return: Dictionary mapping the given nodes to their modified files.
        """
        raise NotImplementedError

    def fetch_head_node(self):
        """
        Fetches and returns the latest node present in the local copy.
        
        :return: Latest node of the local copy.
        """
        raise NotImplementedError

    def fetch_current_node(self):
        """
        Fetches and returns the currently checked out node.
        
        :return: Currently checked out node. 
        """
        raise NotImplementedError

    def fetch_precursor_node(self, node):
        """
        Fetch the precursor node of the specified node.
        
        :param node: Node to get the precursor of. 
        :return: Precuror node.
        """
        raise NotImplementedError

    def fetch_node_contents(self, files, node):
        """
        Fetches the contents of the specified files for the given node.
        
        :param files: Iterable of file paths. 
        :param node: Node to get the contents for.
        :return: Generator that yields file contents.
        """
        raise NotImplementedError

    def checkout_head(self):
        """
        Reverts the repository to the head node.
        
        :return: None
        """
        raise NotImplementedError

    def checkout_node(self, node):
        """
        Reverts the repository to the specified node.
        
        :param node: Node to revert to.
        :return: None
        """
        raise NotImplementedError

    def node_to_date(self, node):
        """
        Returns the date of a revision.
        
        :param node: Node to get the date for.
        :return: datetime.Date
        """
        raise NotImplementedError

    def date_to_node(self, date):
        """
        Returns the latest node for a given date or None if no node exists on the given date.
        
        :param date: Date to get the latest node for, e.g. datetime.Date object. 
        :return: Latest node for the date or None.
        """
        raise NotImplementedError

    def sort_nodes_asc(self, nodes):
        """
        Sorts the nodes in ascending order. The sorting isn't done on the strings, but according to the repository
        history.
        
        :return: The same nodes in ascending order.
        """
        raise NotImplementedError
