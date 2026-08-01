import os
import sys
import pandas as pd
from scipy.stats import ks_2samp

from networksecurity.constant.training_pipeline import SCHEMA_FILE_PATH
from networksecurity.entity.artifact_entity import DataIngestionArtifact, DataValidationArtifact
from networksecurity.entity.config_entity import DataValidationConfig, TrainingPipelineConfig
from networksecurity.exception.exception import NetworkSecurityException 
from networksecurity.logging.logger import logging 
from networksecurity.utils.main_utils.utils import read_yaml_file, write_yaml_file


class DataValidation:
    def __init__(self, data_ingestion_artifact: DataIngestionArtifact,
                 data_validation_config: DataValidationConfig):
        try:
            self.data_ingestion_artifact = data_ingestion_artifact
            self.data_validation_config = data_validation_config
            self._schema_config = read_yaml_file(SCHEMA_FILE_PATH)
        except Exception as e:
            raise NetworkSecurityException(e, sys)
        
    @staticmethod
    def read_data(file_path) -> pd.DataFrame:
        try:
            return pd.read_csv(file_path)
        except Exception as e:
            raise NetworkSecurityException(e, sys)

    def _get_schema_columns(self):
        """Helper method to extract column definitions cleanly from schema configuration."""
        schema_cols = self._schema_config.get("columns", self._schema_config)
        expected_cols = []

        if isinstance(schema_cols, dict):
            expected_cols = list(schema_cols.keys())
        elif isinstance(schema_cols, list):
            for item in schema_cols:
                if isinstance(item, dict):
                    expected_cols.extend(item.keys())
                else:
                    expected_cols.append(item)
        return expected_cols
        
    def validate_number_of_columns(self, dataframe: pd.DataFrame) -> bool:
        """Validates if the dataframe matches the schema column count."""
        try:
            expected_cols = self._get_schema_columns()
            number_of_columns = len(expected_cols)
            df_col_count = len(dataframe.columns)
            
            logging.info(f"Required number of columns: {number_of_columns}")
            logging.info(f"Dataframe has columns: {df_col_count}")
            
            if df_col_count != number_of_columns:
                print(f"[SCHEMA CHECK FAILED] Expected {number_of_columns} columns, but DataFrame has {df_col_count}.")
                return False

            return True
        except Exception as e:
            raise NetworkSecurityException(e, sys)

    def validate_column_names(self, dataframe: pd.DataFrame) -> bool:
        """Validates if expected schema columns exist in the dataframe."""
        try:
            expected_cols = self._get_schema_columns()
            missing_cols = [col for col in expected_cols if col not in dataframe.columns]
            
            if missing_cols:
                logging.error(f"Missing columns in dataframe: {missing_cols}")
                print(f"[SCHEMA CHECK FAILED] Missing columns in DataFrame: {missing_cols}")
                return False
            return True
        except Exception as e:
            raise NetworkSecurityException(e, sys)

    def detect_dataset_drift(self, base_df: pd.DataFrame, current_df: pd.DataFrame, threshold: float = 0.05) -> bool:
        """Detects distribution drift using the 2-sample Kolmogorov-Smirnov test on numerical columns."""
        try:
            status = True
            report = {}
            
            # Filter strictly for numerical columns to avoid Scipy errors on strings/categories
            numerical_columns = base_df.select_dtypes(include=['number']).columns

            for column in numerical_columns:
                if column not in current_df.columns:
                    continue
                
                d1 = base_df[column].dropna()
                d2 = current_df[column].dropna()
                
                is_same_dist = ks_2samp(d1, d2)
                p_value = float(is_same_dist.pvalue)
                
                # Drift detected if p-value is less than threshold
                drift_found = p_value < threshold
                if drift_found:
                    status = False

                report[column] = {
                    "p_value": p_value,
                    "drift_status": drift_found
                }

            drift_report_file_path = self.data_validation_config.drift_report_file_path
            dir_path = os.path.dirname(drift_report_file_path)
            os.makedirs(dir_path, exist_ok=True)
            write_yaml_file(file_path=drift_report_file_path, content=report)
            
            return status

        except Exception as e:
            raise NetworkSecurityException(e, sys)
        
    def initiate_data_validation(self) -> DataValidationArtifact:
        try:
            train_file_path = self.data_ingestion_artifact.trained_file_path
            test_file_path = self.data_ingestion_artifact.test_file_path

            # Read train and test datasets
            train_dataframe = DataValidation.read_data(train_file_path)
            test_dataframe = DataValidation.read_data(test_file_path)
            
            # Step 1: Validate column count & names
            train_col_num = self.validate_number_of_columns(train_dataframe)
            train_col_names = self.validate_column_names(train_dataframe)
            test_col_num = self.validate_number_of_columns(test_dataframe)
            test_col_names = self.validate_column_names(test_dataframe)

            print("\n--- Debug Schema Checks ---")
            print(f"Train Column Count Match : {train_col_num}")
            print(f"Train Column Names Match : {train_col_names}")
            print(f"Test Column Count Match  : {test_col_num}")
            print(f"Test Column Names Match  : {test_col_names}\n")

            validation_status = True
            
            if not train_col_num or not train_col_names:
                validation_status = False
                logging.error("Train dataset failed column schema validation.")

            if not test_col_num or not test_col_names:
                validation_status = False
                logging.error("Test dataset failed column schema validation.")

            # Step 2: Check dataset drift
            drift_status = self.detect_dataset_drift(base_df=train_dataframe, current_df=test_dataframe)
            
            # Combined status: Valid only if schema matches AND no critical drift
            overall_status = validation_status and drift_status

            # Step 3: Save validated dataset or route based on status
            if validation_status:
                valid_train_path = self.data_validation_config.valid_train_file_path
                valid_test_path = self.data_validation_config.valid_test_file_path
                invalid_train_path = None
                invalid_test_path = None

                os.makedirs(os.path.dirname(valid_train_path), exist_ok=True)
                train_dataframe.to_csv(valid_train_path, index=False, header=True)
                test_dataframe.to_csv(valid_test_path, index=False, header=True)
            else:
                valid_train_path = None
                valid_test_path = None
                invalid_train_path = self.data_validation_config.invalid_train_file_path
                invalid_test_path = self.data_validation_config.invalid_test_file_path

                os.makedirs(os.path.dirname(invalid_train_path), exist_ok=True)
                train_dataframe.to_csv(invalid_train_path, index=False, header=True)
                test_dataframe.to_csv(invalid_test_path, index=False, header=True)
            
            data_validation_artifact = DataValidationArtifact(
                validation_status=overall_status,
                valid_train_file_path=valid_train_path,
                valid_test_file_path=valid_test_path,
                invalid_train_file_path=invalid_train_path,
                invalid_test_file_path=invalid_test_path,
                drift_report_file_path=self.data_validation_config.drift_report_file_path,
            )
            
            logging.info(f"Data Validation Artifact created: {data_validation_artifact}")
            return data_validation_artifact

        except Exception as e:
            raise NetworkSecurityException(e, sys)


# ==========================================
# Execution / Driver Block
# ==========================================
if __name__ == "__main__":
    try:
        # 1. Mock the ingestion artifact pointing to existing CSV artifacts
        data_ingestion_artifact = DataIngestionArtifact(
            trained_file_path=r"Artifacts\07_30_2026_15_50_49\data_ingestion\ingested\train.csv",
            test_file_path=r"Artifacts\07_30_2026_15_50_49\data_ingestion\ingested\test.csv"
        )

        # 2. Initialize configuration objects
        training_pipeline_config = TrainingPipelineConfig()
        data_validation_config = DataValidationConfig(training_pipeline_config=training_pipeline_config)

        # 3. Instantiate and trigger Data Validation
        data_validation = DataValidation(
            data_ingestion_artifact=data_ingestion_artifact,
            data_validation_config=data_validation_config
        )

        print("Starting Data Validation execution...")
        data_validation_artifact = data_validation.initiate_data_validation()
        
        print("\n--- Data Validation Completed Successfully! ---")
        print(f"Validation Status : {data_validation_artifact.validation_status}")
        print(f"Valid Train Path  : {data_validation_artifact.valid_train_file_path}")
        print(f"Valid Test Path   : {data_validation_artifact.valid_test_file_path}")
        print(f"Drift Report Path : {data_validation_artifact.drift_report_file_path}")

    except Exception as e:
        raise NetworkSecurityException(e, sys)