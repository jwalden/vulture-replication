import time
import numpy as np
from sklearn import svm
from sklearn import tree
import copy

from matrix_helper import MatrixHelper

class PredictionHelper:

    def __init__(self):
        self.matrix_helper = MatrixHelper()
        self.compare_matrix = None
        self.time = None
        self.most_important_feature_index = None
        self.most_important_feature = None

    def calculate_validation_compare_matrix(self, matrices, sampling_factor=(2.0/3), prediction_type='SVM', crop_matrix=False, penalty=1.0):
        """
        Creates a comparison matrix on a single revision. The feature matrix of
        this revision is splitted into training and test set by stratified sampling
        with the given factor.
        The comparison matrix contains the following 3 columns:
        [:, 0] = component name
        [:, 1] = predicted number of vulnerabilities
        [:, 2] = actual number of vulnerabilities in test set

        :param matrices: A tuple that contains the feature matrix and the row names of all components
        of a revision, that will be used to predict vulnerabilities.
        :param sampling_factor: Factor that is used for the stratified sampling.
        :param prediction_type: Classifier or Regression type.
        :param crop_matrix: If true, the feature matrix is croped to 1000 samples
        to reduce the prediction time.
        :param penalty: Penalty parameter C for the classification model.
        :return: None
        """
        feature_matrix = matrices[0]
        if (crop_matrix):
            feature_matrix = feature_matrix[:1000, :]
        rows = matrices[1]
        columns = matrices[2]
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
        target_prediction, time = self.predict(training_data, training_target, test_data, prediction_type, penalty)

        if self.most_important_feature_index is not None:
            self.most_important_feature = columns[self.most_important_feature_index]

        # Create matrix with component names, predicted vulnerabilities and actual number of vulnerabilities in test set
        compare_matrix = []

        for i in range(len(target_prediction)):
            compare_matrix.append([test_rows[i], round(float(target_prediction[i])), test_target[i]])

        self.compare_matrix = np.array(compare_matrix)
        self.time = time

    def calculate_semiannual_compare_matrix(self, matrices, validation_matrices, prediction_type='LinearSVC', penalty=1.0):
        """
        Creates a comparison matrix on two different revisions. With the feature
        matrix of an old revision, a model is fitted and applied to all components
        of the same revision that had no vulnerabilities at this moment.
        In the comparison matrix, this predicted vulnerabilities are compared
        with the actual vulnerabilities of the same components in a later revision.
        The comparison matrix contains the following 3 columns:
        [:, 0] = component name
        [:, 1] = predicted number of vulnerabilities
        [:, 2] = actual number of vulnerabilities in validation revision

        :param matrices: A tuple that contains the feature matrix and the row names of all components
        of the first revision, that will be used to predict future vulnerabilities.
        :param validation_matrices: A tuple that contains the feature matrix and the row names of all components
        of the validation revision, that will be used for validating the prediciton.
        :param prediction_type: Classifier or Regression type.
        :param penalty: Penalty parameter C for the classification model.
        :return: None
        """
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
        target_prediction, time = self.predict(training_data, training_target, not_vulnerable_matrix[:, range(features_count)], prediction_type, penalty)

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
        self.time = time

    def predict(self, training_data, training_target, test_data, prediction_type, penalty):
        """
        Fits an SVM, SVR or a decision tree with the given training data and calculates
        the prediction for the test data.

        :param training_data: The matrix with that the model is fitted without the target.
        :param training_target: The target vector with that the model is fitted.
        :param test_data: The test matrix data for that the prediction is calculated.
        :param prediction_type: Classifier or Regression type.
        :param penalty: Penalty parameter C for the classification model.
        :return: A target vector with the predicted values and the elapsed time for
        calculation in seconds.
        """
        start = time.time()

        # Create the SVM or DT
        if (prediction_type == 'SVM'):
            m = svm.SVC(kernel='linear', C=penalty)
        elif (prediction_type == 'LinearSVC'):
            m = svm.LinearSVC(C=penalty)
        elif (prediction_type == 'DT'):
            m = tree.DecisionTreeClassifier()
        else:
            m = svm.LinearSVR(C=penalty)

        # Fit prediction_type to the model
        m.fit(training_data, training_target)

        # Predict remaining data
        target_prediction = m.predict(test_data)

        end = time.time()
        elapsed = (end - start) / 60

        if (prediction_type == 'DT'):
            self.most_important_feature_index = m.tree_.feature[0]

        return target_prediction, elapsed

    def get_compare_matrix(self, with_deleted_components=False):
        if (with_deleted_components):
            return self.compare_matrix_with_deleted
        return self.compare_matrix

    def get_compare_matrix_sorted(self, reference_column=1, with_deleted_components=False):
        """
        Sorts the calculated compare matrix according to target prediction value
        (number of predicted vulnerabilities for each component) and returns it.

        :param with_deleted_components: If true, in the semiannual comparaison
        are components that were deleted in the later revision, still displayed
        in the compare matrix.
        :return: A sorted copy of the compare matrix.
        """
        if (with_deleted_components and self.compare_matrix_with_deleted is not None):
            sorted_indeces = np.array(self.compare_matrix_with_deleted[:,reference_column], dtype='f').argsort()[::-1]
            return copy.copy(self.compare_matrix_with_deleted[sorted_indeces])

        sorted_indeces = np.array(self.compare_matrix[:,reference_column], dtype='f').argsort()[::-1]
        return copy.copy(self.compare_matrix[sorted_indeces])

    def get_compare_matrix_top(self, percent=0.01, with_deleted_components=False):
        """
        Return a percentage (highest x percent) of the sorted compare matrix.

        :param percent: Percentage of predicted components that will be returned.
        :param with_deleted_components: If true, in the semiannual comparaison
        are components that were deleted in the later revision, still displayed
        in the compare matrix.
        :return: Highest x percent of the sorted compare matrix.
        """
        compare_matrix_sorted = self.get_compare_matrix_sorted(with_deleted_components)
        actual_samples_count = len(compare_matrix_sorted[:,0])
        relevant_samples_count = int(round(percent * actual_samples_count))
        return compare_matrix_sorted[range(relevant_samples_count), :]
