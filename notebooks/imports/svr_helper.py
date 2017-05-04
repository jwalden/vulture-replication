import numpy as np
from sklearn.svm import LinearSVR
import copy

class SVRHelper:

    def __init__(self, matrices, validation_matrices):
        self.feature_matrix = matrices[0]
        self.validation_feature_matrix = validation_matrices[0]
        self.rows = matrices[1]
        self.validation_rows = validation_matrices[1]
        self.features_count = self.feature_matrix.shape[1] - 1
        self.compare_matrix = None
        self.compare_matrix_with_deleted = None

    def calculate_compare_matrix(self):
        # Create Array (vulnerable_rows) with the names of all vulnerable components
        vulnerable_indices = np.where(self.feature_matrix[:,-1] > 0)
        vulnerable_rows = [self.rows[i] for i in (vulnerable_indices[0])]

        # Create 2 matrices: One with the NOT vulnerable samples/components and one with their names
        not_vulnerable_rows = []
        not_vulnerable_matrix = []

        for i in range(len(self.rows)):
            if self.rows[i] not in vulnerable_rows:
                not_vulnerable_rows.append(self.rows[i])
                not_vulnerable_matrix.append(self.feature_matrix[i,:])

        not_vulnerable_matrix = np.asarray(not_vulnerable_matrix)

        # Split feature matrix into data and target
        training_data = self.feature_matrix[:, range(self.features_count)]
        training_target = self.feature_matrix[:, self.features_count]

        # Create support vector regression
        svr = LinearSVR(C=0.2)

        # Fit model
        svr.fit(training_data, training_target)

        # Predict target for all components without any known vulnerabilities
        target_prediction = svr.predict(not_vulnerable_matrix[:, range(self.features_count)])

        # Create matrix with component names, predicted vulnerabilities and actual number of vulnerabilities in validation revision
        compare_matrix = []
        compare_matrix_with_deleted = []
        for i in range(len(not_vulnerable_rows)):
            if not_vulnerable_rows[i] in self.validation_rows:
                validation_index = self.validation_rows.index(not_vulnerable_rows[i])
                compare_matrix.append([not_vulnerable_rows[i], target_prediction[i], self.validation_feature_matrix[validation_index, -1]])
                compare_matrix_with_deleted.append([not_vulnerable_rows[i], target_prediction[i], self.validation_feature_matrix[validation_index, -1]])
            else:
                compare_matrix_with_deleted.append([not_vulnerable_rows[i], target_prediction[i], 'Deleted'])

        self.compare_matrix = np.array(compare_matrix)
        self.compare_matrix_with_deleted = np.array(compare_matrix_with_deleted)

    def get_compare_matrix(self, with_deleted_components=False):
        if (with_deleted_components):
            return self.compare_matrix_with_deleted
        return self.compare_matrix

    def get_compare_matrix_sorted(self, with_deleted_components=False):
        if (with_deleted_components):
            sorted_indeces = np.array(self.compare_matrix_with_deleted[:,1], dtype='f').argsort()[::-1]
            return copy.copy(self.compare_matrix_with_deleted[sorted_indeces])

        sorted_indeces = np.array(self.compare_matrix[:,1], dtype='f').argsort()[::-1]
        return copy.copy(self.compare_matrix[sorted_indeces])

    def get_compare_matrix_top(self, percent=0.01, with_deleted_components=False):
        compare_matrix_sorted = self.get_compare_matrix_sorted(with_deleted_components)
        actual_samples_count = len(compare_matrix_sorted[:,0])
        relevant_samples_count = int(round(percent * actual_samples_count))
        return compare_matrix_sorted[range(relevant_samples_count), :]
