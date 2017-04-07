import numpy as np
import cPickle as pickle


def get_matrices(path):
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
