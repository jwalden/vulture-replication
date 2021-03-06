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
        self.time_fitting = None
        self.time_predicting = None
        self.most_important_feature_index = None
        self.most_important_feature = None

    def calculate_validation_compare_matrix(self, matrices, sampling_factor=(2.0/3), model_type='LinearSVC', crop_matrix=-1, penalty=0.1):
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
        :param model_type: Classifier or Regression type.
        :param crop_matrix: If value is set, the feature matrix is croped to the number of given samples
        to reduce the fitting time.
        :param penalty: Penalty parameter C for the classification model.
        :return: None
        """
        feature_matrix = matrices[0]
        if (crop_matrix >= 0 and crop_matrix < feature_matrix.shape[0]):
            feature_matrix = feature_matrix[:crop_matrix, :]
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
        target_prediction, time = self.predict(training_data, training_target, test_data, model_type, penalty)

        if self.most_important_feature_index is not None:
            self.most_important_feature = columns[self.most_important_feature_index]

        # Create matrix with component names, predicted vulnerabilities and actual number of vulnerabilities in test set
        compare_matrix = []

        for i in range(len(target_prediction)):
            compare_matrix.append([test_rows[i], round(float(target_prediction[i])), test_target[i]])

        self.compare_matrix = np.array(compare_matrix)
        self.time_fitting = time[0]
        self.time_predicting = time[1]

    def calculate_semiannual_compare_matrix(self, matrices, validation_matrices, model_type='LinearSVR', penalty=0.1):
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
        :param model_type: Classifier or Regression type.
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
        target_prediction, time = self.predict(training_data, training_target, not_vulnerable_matrix[:, range(features_count)], model_type, penalty)

        # Create matrix with component names, predicted vulnerabilities and actual number of vulnerabilities in validation revision
        compare_matrix = []
        compare_matrix_with_deleted = []
        for i in range(len(not_vulnerable_rows)):
            if not_vulnerable_rows[i] in validation_rows:
                validation_indices = np.where(np.array(validation_rows)==not_vulnerable_rows[i])[0]
                validation_index_max = validation_indices[np.argmax(validation_feature_matrix[validation_indices, -1])]

                compare_matrix.append([not_vulnerable_rows[i], round(float(target_prediction[i])), validation_feature_matrix[validation_index_max, -1]])
                compare_matrix_with_deleted.append([not_vulnerable_rows[i], round(float(target_prediction[i])), validation_feature_matrix[validation_index_max, -1]])
            else:
                compare_matrix_with_deleted.append([not_vulnerable_rows[i], round(float(target_prediction[i])), 'Deleted'])

        self.compare_matrix = np.array(compare_matrix)
        self.compare_matrix_with_deleted = np.array(compare_matrix_with_deleted)
        self.time_fitting = time[0]
        self.time_predicting = time[1]

    def predict(self, training_data, training_target, test_data, model_type, penalty):
        """
        Fits an SVM, SVR or a decision tree with the given training data and calculates
        the prediction for the test data.

        :param training_data: The matrix with that the model is fitted without the target.
        :param training_target: The target vector with that the model is fitted.
        :param test_data: The test matrix data for that the prediction is calculated.
        :param model_type: Classifier or Regression type.
        :param penalty: Penalty parameter C for the classification model.
        :return: A target vector with the predicted values and the elapsed time for
        calculation in seconds.
        """
        start = time.time()

        # Create the SVM or DT
        if (model_type == 'SVM'):
            m = svm.SVC(kernel='linear', C=penalty)
        elif (model_type == 'LinearSVC'):
            m = svm.LinearSVC(C=penalty)
        elif (model_type == 'DT'):
            m = tree.DecisionTreeClassifier()
        else:
            m = svm.LinearSVR(C=penalty)

        # Fit data to the model
        m.fit(training_data, training_target)
        end_fitting = time.time()

        # Predict remaining data
        target_prediction = m.predict(test_data)
        end_predicting = time.time()

        elapsed_fitting = (end_fitting - start)
        elapsed_predicting = (end_predicting - end_fitting)


        if (model_type == 'DT'):
            self.most_important_feature_index = m.tree_.feature[0]

        return target_prediction, (elapsed_fitting, elapsed_predicting)

    def get_compare_matrix(self, with_deleted_components=False):
        """
        Returns the calculated compare matric with or without a "deleted" entry
        fpr delted components.

        :param with_deleted_components: If true, in the semiannual comparaison
        are components that were deleted in the later revision, still displayed
        in the compare matrix.
        :return: The compare matrix.
        """
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
