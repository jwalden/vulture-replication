import numpy as np
from sklearn.svm import LinearSVR
import copy

from matrix_helper import MatrixHelper

class SVRHelper:

    def __init__(self):
        self.matrix_helper = MatrixHelper()
        self.compare_matrix = None
        self.compare_matrix_with_deleted = None

    def calculate_validation_compare_matrix(self, matrices, sampling_factor=(2.0/3)):
        '''
        Erstellt eine Vergleichsmatrix auf der feature matrix einer einzelnen Revision mit folgenden 3 Spalten:
        [:, 0] = Name der Komponente
        [:, 1] = Vorhergesagte Anzahl Verwundbarkeiten aufgrund des Regressionsmodells
        [:, 2] = Tatsaechliche Anzahl Verwundbarkeiten im Testset

        Dabei wird die feature matrix mit stratified sampling gemaess dem uebergebenen Faktor in training und test set aufgeteilt.
        '''
        feature_matrix = matrices[0]
        rows = matrices[1]
        features_count = feature_matrix.shape[1] - 1

        # Create own matrices for vulenrable and not vulnerable entries
        vulnerable_matrix, vulnerable_rows = self.matrix_helper.get_vulnerable_components(feature_matrix, rows)
        not_vulnerable_matrix, not_vulnerable_rows = self.matrix_helper.get_not_vulnerable_components(feature_matrix, rows)

        # Split into training sets (2/3) and test sets (1/3)
        vulnerable_training, vulnerable_test = self.matrix_helper.split_training_test(vulnerable_matrix, sampling_factor, vulnerable_rows)
        not_vulnerable_training, not_vulnerable_test = self.matrix_helper.split_training_test(not_vulnerable_matrix, sampling_factor, not_vulnerable_rows)

        # Concatenate vulnerable/not-vulnerable
        training_matrix = np.concatenate((not_vulnerable_training[0], vulnerable_training[0]), axis=0)
        test_matrix = np.concatenate((not_vulnerable_test[0], vulnerable_test[0]), axis=0)
        test_rows = not_vulnerable_test[1] + vulnerable_test[1]

        # Split into training and target matrices
        training_data, training_target = self.matrix_helper.create_data_target(training_matrix)
        test_data, test_target = self.matrix_helper.create_data_target(test_matrix)

        # Train SVR Model and predict vulnerrabilities for test data
        target_prediction = self.predict(training_data, training_target, test_data[:, range(features_count)])

        # Create matrix with component names, predicted vulnerabilities and actual number of vulnerabilities in test set
        compare_matrix = []

        for i in range(len(target_prediction)):
            compare_matrix.append([test_rows[i], round(float(target_prediction[i])), test_target[i]])

        self.compare_matrix = np.array(compare_matrix)
        self.compare_matrix_with_deleted = None


    def calculate_semiannual_compare_matrix(self, matrices, validation_matrices):
        '''
        Erstellt eine Vergleichsmatrix fuer zwei verschiedene Revisionen. Mit der feature matrix
        einer alten Revision wird ein Regressionsmodell angelernt und auf alle Komponenten der selben
        Revision angewendet, die zu deren Zeitpunkt keine Verwundbarkeiten hatten. In der Vergleichsmatrix
        werden die vorhergesagten Verwundbarkeiten mit den tatsaechlichen Verwundbarkeiten der gleichen
        Komponenten zu einer spaeteren Revision verglichen. Die Vergleichsmatrix enthaelt folgende 3 Spalten:
        [:, 0] = Name der Komponente
        [:, 1] = Vorhergesagte Anzahl Verwundbarkeiten aufgrund des Regressionsmodells
        [:, 2] = Tatsaechliche Anzahl Verwundbarkeiten in der spaeteren regression (validation_matrices)
        '''
        feature_matrix = matrices[0]
        validation_feature_matrix = validation_matrices[0]
        rows = matrices[1]
        validation_rows = validation_matrices[1]
        features_count = feature_matrix.shape[1] - 1

        # Get all components that haven't any known vulnerabilities
        (not_vulnerable_matrix, not_vulnerable_rows) = self.matrix_helper.get_components_without_vulnerabilities(feature_matrix, rows)

        # Split feature matrix into data and target
        training_data, training_target = self.matrix_helper.create_data_target(feature_matrix)

        # Train SVR Model and predict vulnerrabilities for all components without any vulnerabilities
        target_prediction = self.predict(training_data, training_target, not_vulnerable_matrix[:, range(features_count)])

        # Create matrix with component names, predicted vulnerabilities and actual number of vulnerabilities in validation revision
        compare_matrix = []
        compare_matrix_with_deleted = []
        for i in range(len(not_vulnerable_rows)):
            if not_vulnerable_rows[i] in validation_rows:
                validation_index = validation_rows.index(not_vulnerable_rows[i])
                compare_matrix.append([not_vulnerable_rows[i], round(float(target_prediction[i])), validation_feature_matrix[validation_index, -1]])
                compare_matrix_with_deleted.append([not_vulnerable_rows[i], round(float(target_prediction[i])), validation_feature_matrix[validation_index, -1]])
            else:
                compare_matrix_with_deleted.append([not_vulnerable_rows[i], round(float(target_prediction[i])), 'Deleted'])

        self.compare_matrix = np.array(compare_matrix)
        self.compare_matrix_with_deleted = np.array(compare_matrix_with_deleted)


    def predict(self, training_data, training_target, test_data):
        # Create support vector regression
        svr = LinearSVR(C=0.2)

        # Fit model
        svr.fit(training_data, training_target)

        # Predict target for all components without any known vulnerabilities
        target_prediction = svr.predict(test_data)

        return target_prediction


    def get_compare_matrix(self, with_deleted_components=False):
        if (with_deleted_components):
            return self.compare_matrix_with_deleted
        return self.compare_matrix

    def get_compare_matrix_sorted(self, with_deleted_components=False):
        if (with_deleted_components and self.compare_matrix_with_deleted != None):
            sorted_indeces = np.array(self.compare_matrix_with_deleted[:,1], dtype='f').argsort()[::-1]
            return copy.copy(self.compare_matrix_with_deleted[sorted_indeces])

        sorted_indeces = np.array(self.compare_matrix[:,1], dtype='f').argsort()[::-1]
        return copy.copy(self.compare_matrix[sorted_indeces])

    def get_compare_matrix_top(self, percent=0.01, with_deleted_components=False):
        compare_matrix_sorted = self.get_compare_matrix_sorted(with_deleted_components)
        actual_samples_count = len(compare_matrix_sorted[:,0])
        relevant_samples_count = int(round(percent * actual_samples_count))
        return compare_matrix_sorted[range(relevant_samples_count), :]
