import time
import numpy as np
from sklearn import svm
from sklearn import tree
import copy

from matrix_helper import MatrixHelper

class ClassificationHelper:

    def __init__(self):
        self.matrix_helper = MatrixHelper()
        self.compare_matrix = None
        self.time = None

    def calculate_validation_compare_matrix(self, matrices, sampling_factor=(2.0/3), prediction_type='SVM', crop_matrix=False):
        '''
        Erstellt eine Vergleichsmatrix auf der feature matrix einer einzelnen Revision mit folgenden 3 Spalten:
        [:, 0] = Name der Komponente
        [:, 1] = Vorhergesagte Anzahl Verwundbarkeiten aufgrund des Regressionsmodells
        [:, 2] = Tatsaechliche Anzahl Verwundbarkeiten im Testset

        Dabei wird die feature matrix mit stratified sampling gemaess dem uebergebenen Faktor in training und test set aufgeteilt.
        '''
        feature_matrix = matrices[0]
        if (crop_matrix):
            feature_matrix = feature_matrix[:1000, :]
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


        # Train the classification model and predict vulnerrabilities for test data
        target_prediction, time = self.predict(training_data, training_target, test_data, prediction_type)

        # Create matrix with component names, predicted vulnerabilities and actual number of vulnerabilities in test set
        compare_matrix = []

        for i in range(len(target_prediction)):
            compare_matrix.append([test_rows[i], round(float(target_prediction[i])), test_target[i]])

        self.compare_matrix = np.array(compare_matrix)
        self.time = time

    def predict(self, training_data, training_target, test_data, prediction_type):
        start = time.time()

        # Create the SVM or DT
        if (prediction_type == 'SVM'):
            m = svm.SVC(kernel='linear', C=0.2)
        elif (prediction_type == 'DT'):
            m = tree.DecisionTreeClassifier()
        else:
            m = svm.LinearSVR(C=0.2)

        # Fit prediction_type to the model
        m.fit(training_data, training_target)

        # Predict remaining data
        target_prediction = m.predict(test_data)

        end = time.time()
        elapsed = (end - start) / 60

        return target_prediction, elapsed

    def get_compare_matrix(self, with_deleted_components=False):
        if (with_deleted_components):
            return self.compare_matrix_with_deleted
        return self.compare_matrix

    def get_compare_matrix_sorted(self, with_deleted_components=False):
        if (with_deleted_components and self.compare_matrix_with_deleted is not None):
            sorted_indeces = np.array(self.compare_matrix_with_deleted[:,1], dtype='f').argsort()[::-1]
            return copy.copy(self.compare_matrix_with_deleted[sorted_indeces])

        sorted_indeces = np.array(self.compare_matrix[:,1], dtype='f').argsort()[::-1]
        return copy.copy(self.compare_matrix[sorted_indeces])

    def get_compare_matrix_top(self, percent=0.01, with_deleted_components=False):
        compare_matrix_sorted = self.get_compare_matrix_sorted(with_deleted_components)
        actual_samples_count = len(compare_matrix_sorted[:,0])
        relevant_samples_count = int(round(percent * actual_samples_count))
        return compare_matrix_sorted[range(relevant_samples_count), :]
