import numpy as np
import cPickle as pickle

class MatrixHelper:
    def load_from_parse(self, path):
        matrix = None
        with open(path, 'rb') as f:
            sparse = pickle.load(f)

        rows = sparse[2]
        columns = sparse[3]
        matrix = np.zeros((len(rows), len(columns) + 1), dtype=np.uint8)
        matrix[:,-1:] = sparse[1]
        for i, j in sparse[0]:
            matrix[i, j] = 1

        return (matrix, rows, columns)

    def get_not_vulnerable_components(self, matrix, rows):
        """
        Gibt alle Samples und die zugehoerigen Komponentennamen zurueck, deren
        vulnerability counter == 0 ist.
        """

        not_vulnerable_indices = np.where(matrix[:,-1] == 0)
        not_vulnerable_rows = [rows[i] for i in (not_vulnerable_indices[0])]
        not_vulnerable_matrix  = (matrix[not_vulnerable_indices,:])[0]

        return (not_vulnerable_matrix, not_vulnerable_rows)

    def get_vulnerable_components(self, matrix, rows):
        """
        Gibt alle Samples und die zugehoerigen Komponentennamen zurueck, deren
        vulnerability counter > 0 ist.
        """

        vulnerable_indices = np.where(matrix[:,-1] > 0)
        vulnerable_rows = [rows[i] for i in (vulnerable_indices[0])]
        vulnerable_matrix  = (matrix[vulnerable_indices,:])[0]

        return (vulnerable_matrix, vulnerable_rows)

    def get_components_without_vulnerabilities(self, matrix, rows):
        """
        Gibt alle Samples und die zugehoerigen Komponentennamen zurueck, fuer die
        es KEINEN verwundbaren Eintrag in der Matrix gibt. Einmal Verwundbar,
        bleibt sie es auch.
        """

        # Create Array (vulnerable_rows) with the names of all vulnerable components
        vulnerable_indices = np.where(matrix[:,-1] > 0)
        vulnerable_rows = [rows[i] for i in (vulnerable_indices[0])]

        # Create 2 matrices: One with the NOT vulnerable samples/components and one with their names
        not_vulnerable_rows = []
        not_vulnerable_matrix = []

        for i in range(len(rows)):
            if rows[i] not in vulnerable_rows:
                not_vulnerable_rows.append(rows[i])
                not_vulnerable_matrix.append(matrix[i,:])

        not_vulnerable_matrix = np.asarray(not_vulnerable_matrix)

        return (not_vulnerable_matrix, not_vulnerable_rows)

    def split_training_test(self, matrix, sampling_factor=(2.0/3), rows=None):
        samples_count = matrix.shape[0]

        random_indices = np.random.choice(samples_count, int(samples_count * sampling_factor), replace=False)
        rest_of_list_indices = [item for item in range(samples_count) if item not in random_indices]

        training_matrix = matrix[random_indices, :]
        test_matrix = matrix[rest_of_list_indices, :]

        if rows == None:
            return training_matrix, test_matrix

        training_rows = [rows[i] for i in random_indices]
        test_rows = [rows[i] for i in rest_of_list_indices]

        return (training_matrix, training_rows), (test_matrix, test_rows)

    def create_data_target(self, matrix):
        features_count = matrix.shape[1] - 1

        data = matrix[:, range(features_count)]
        target = matrix[:, features_count]
        return data, target

    def get_vulnerable_percentage(self, matrix):
        return (matrix[matrix > 0]).size * 100.0 / matrix.size
