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

    def split_vulnerable_notvulnerable(self, matrix):
        vulnerable = (matrix[np.where(matrix[:,-1] > 0),:])[0]
        not_vulnerable = (matrix[np.where(matrix[:,-1] == 0),:])[0]

        return vulnerable, not_vulnerable

    def split_training_test(self, matrix, part_training):
        samples_count = matrix.shape[0]

        random_part = np.random.choice(samples_count, int(samples_count * part_training), replace=False)
        rest_of_list = [item for item in range(samples_count) if item not in random_part]

        training = matrix[random_part, :]
        test = matrix[rest_of_list, :]

        return training, test

    def create_data_target(self, not_vulnerable, vulnerable):
        matrix = np.concatenate((not_vulnerable, vulnerable), axis=0)
        features_count = matrix.shape[1] - 1

        data = matrix[:, range(features_count)]
        target = matrix[:, features_count]
        return data, target

    def get_vulnerable_percentage(self, matrix):
        return (matrix[matrix > 0]).size * 100.0 / matrix.size
