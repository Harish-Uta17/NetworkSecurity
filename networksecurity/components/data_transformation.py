import sys
import os
import glob
import numpy as np
import pandas as pd
from sklearn.impute import KNNImputer
from sklearn.pipeline import Pipeline

from networksecurity.constant.training_pipeline import TARGET_COLUMN
from networksecurity.constant.training_pipeline import DATA_TRANSFORMATION_IMPUTER_PARAMS

from networksecurity.entity.artifact_entity import (
    DataTransformationArtifact,
    DataValidationArtifact
)

from networksecurity.entity.config_entity import DataTransformationConfig, TrainingPipelineConfig
from networksecurity.exception.exception import NetworkSecurityException 
from networksecurity.logging.logger import logging
from networksecurity.utils.main_utils.utils import save_numpy_array_data, save_object


class DataTransformation:
    def __init__(self, data_validation_artifact: DataValidationArtifact,
                 data_transformation_config: DataTransformationConfig):
        try:
            self.data_validation_artifact: DataValidationArtifact = data_validation_artifact
            self.data_transformation_config: DataTransformationConfig = data_transformation_config
        except Exception as e:
            raise NetworkSecurityException(e, sys)
        
    @staticmethod
    def read_data(file_path) -> pd.DataFrame:
        try:
            return pd.read_csv(file_path)
        except Exception as e:
            raise NetworkSecurityException(e, sys)
        
    def get_data_transformer_object(self) -> Pipeline:
        """
        Initializes a KNNImputer object with parameters specified in training_pipeline
        and returns a Pipeline object.
        """
        logging.info("Entered get_data_transformer_object method of DataTransformation class")
        try:
            imputer: KNNImputer = KNNImputer(**DATA_TRANSFORMATION_IMPUTER_PARAMS)
            logging.info(f"Initialized KNNImputer with parameters: {DATA_TRANSFORMATION_IMPUTER_PARAMS}")
            
            processor: Pipeline = Pipeline([("imputer", imputer)])
            return processor
        except Exception as e:
            raise NetworkSecurityException(e, sys)

    def initiate_data_transformation(self) -> DataTransformationArtifact:
        logging.info("Entered initiate_data_transformation method of DataTransformation class")
        try:
            logging.info("Starting data transformation process...")
            train_df = DataTransformation.read_data(self.data_validation_artifact.valid_train_file_path)
            test_df = DataTransformation.read_data(self.data_validation_artifact.valid_test_file_path)

            # Drop target column & automatically filter out string/categorical columns (url, domain, tld)
            drop_columns = [TARGET_COLUMN]
            string_cols = train_df.select_dtypes(include=['object', 'string']).columns.tolist()
            if string_cols:
                logging.info(f"Filtering out non-numerical string features for imputer: {string_cols}")
                drop_columns.extend(string_cols)

            # Extract features and targets for training dataset
            input_feature_train_df = train_df.drop(columns=drop_columns, errors='ignore')
            target_feature_train_df = train_df[TARGET_COLUMN].replace(-1, 0)

            # Extract features and targets for testing dataset
            input_feature_test_df = test_df.drop(columns=drop_columns, errors='ignore')
            target_feature_test_df = test_df[TARGET_COLUMN].replace(-1, 0)

            # Fit-transform features using the preprocessor pipeline
            preprocessor = self.get_data_transformer_object()
            preprocessor_object = preprocessor.fit(input_feature_train_df)
            
            transformed_input_train_feature = preprocessor_object.transform(input_feature_train_df)
            transformed_input_test_feature = preprocessor_object.transform(input_feature_test_df)

            # Combine transformed feature matrices with target labels
            train_arr = np.c_[transformed_input_train_feature, np.array(target_feature_train_df)]
            test_arr = np.c_[transformed_input_test_feature, np.array(target_feature_test_df)]

            # Safe Directory Check & Creation for Artifacts
            transformed_train_dir = os.path.dirname(self.data_transformation_config.transformed_train_file_path)
            transformed_test_dir = os.path.dirname(self.data_transformation_config.transformed_test_file_path)
            transformed_obj_dir = os.path.dirname(self.data_transformation_config.transformed_object_file_path)

            os.makedirs(transformed_train_dir, exist_ok=True)
            os.makedirs(transformed_test_dir, exist_ok=True)
            os.makedirs(transformed_obj_dir, exist_ok=True)

            # Save transformed numpy arrays
            save_numpy_array_data(self.data_transformation_config.transformed_train_file_path, array=train_arr)
            save_numpy_array_data(self.data_transformation_config.transformed_test_file_path, array=test_arr)
            
            # Save preprocessor object in pipeline artifact path
            save_object(self.data_transformation_config.transformed_object_file_path, preprocessor_object)

            # Safe Directory Check & Overwrite for Deployment Folder ('final_model/')
            final_model_dir = "final_model"
            os.makedirs(final_model_dir, exist_ok=True)
            final_preprocessor_path = os.path.join(final_model_dir, "preprocessor.pkl")

            # Overwrite old preprocessor object safely
            save_object(final_preprocessor_path, preprocessor_object)
            logging.info(f"Successfully updated deployment preprocessor at: {final_preprocessor_path}")

            # Construct DataTransformationArtifact entity
            data_transformation_artifact = DataTransformationArtifact(
                transformed_object_file_path=self.data_transformation_config.transformed_object_file_path,
                transformed_train_file_path=self.data_transformation_config.transformed_train_file_path,
                transformed_test_file_path=self.data_transformation_config.transformed_test_file_path
            )
            
            logging.info(f"Data Transformation Artifact created: {data_transformation_artifact}")
            return data_transformation_artifact

        except Exception as e:
            raise NetworkSecurityException(e, sys)


# ==========================================
# Execution / Driver Block (Manual Run)
# ==========================================
if __name__ == "__main__":
    try:
        # Dynamically locate the latest timestamp folder in 'Artifacts'
        artifacts_dir = "Artifacts"
        subdirs = [os.path.join(artifacts_dir, d) for d in os.listdir(artifacts_dir) if os.path.isdir(os.path.join(artifacts_dir, d))]
        
        if not subdirs:
            raise Exception("No artifact directory found in Artifacts folder!")
            
        latest_artifact_dir = max(subdirs, key=os.path.getmtime)
        
        valid_train_path = os.path.join(latest_artifact_dir, "data_validation", "validated", "train.csv")
        valid_test_path = os.path.join(latest_artifact_dir, "data_validation", "validated", "test.csv")
        drift_report_path = os.path.join(latest_artifact_dir, "data_validation", "drift_report", "report.yaml")

        print(f"Using latest validated artifacts from: {latest_artifact_dir}")

        # Create mock DataValidationArtifact
        data_validation_artifact = DataValidationArtifact(
            validation_status=True,
            valid_train_file_path=valid_train_path,
            valid_test_file_path=valid_test_path,
            invalid_train_file_path=None,
            invalid_test_file_path=None,
            drift_report_file_path=drift_report_path
        )

        # Initialize Configs & Class
        training_pipeline_config = TrainingPipelineConfig()
        data_transformation_config = DataTransformationConfig(training_pipeline_config=training_pipeline_config)

        data_transformation = DataTransformation(
            data_validation_artifact=data_validation_artifact,
            data_transformation_config=data_transformation_config
        )

        # Trigger Data Transformation
        print("Starting Data Transformation execution...")
        transformation_artifact = data_transformation.initiate_data_transformation()
        
        print("\n--- Data Transformation Completed Successfully! ---")
        print(f"Transformed Train Array Path : {transformation_artifact.transformed_train_file_path}")
        print(f"Transformed Test Array Path  : {transformation_artifact.transformed_test_file_path}")
        print(f"Preprocessor Object Path     : {transformation_artifact.transformed_object_file_path}")

    except Exception as e:
        raise NetworkSecurityException(e, sys)