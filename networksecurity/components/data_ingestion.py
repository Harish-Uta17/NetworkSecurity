import os
import sys
import numpy as np
import pandas as pd
import pymongo
from typing import List
from sklearn.model_selection import train_test_split

from dotenv import load_dotenv
import certifi

from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging
from networksecurity.entity.config_entity import DataIngestionConfig, TrainingPipelineConfig
from networksecurity.entity.artifact_entity import DataIngestionArtifact

load_dotenv()
MONGO_DB_URL = os.getenv("MONGO_DB_URL")
ca = certifi.where()


class DataIngestion:
    def __init__(self, data_ingestion_config: DataIngestionConfig):
        try:
            self.data_ingestion_config = data_ingestion_config
        except Exception as e:
            raise NetworkSecurityException(e, sys)

    def export_collection_as_dataframe(self) -> pd.DataFrame:
        """Read data from MongoDB Atlas collection into a Pandas DataFrame."""
        try:
            database_name = self.data_ingestion_config.database_name
            collection_name = self.data_ingestion_config.collection_name

            if not MONGO_DB_URL:
                raise Exception("MONGO_DB_URL is not set. Please set it in your .env file")

            self.mongo_client = pymongo.MongoClient(MONGO_DB_URL, tls=True, tlsCAFile=ca)
            collection = self.mongo_client[database_name][collection_name]

            df = pd.DataFrame(list(collection.find()))
            
            if df.empty:
                raise Exception(f"No records found in database: {database_name}, collection: {collection_name}")

            if "_id" in df.columns.to_list():
                df = df.drop(columns=["_id"])

            df.replace({"na": np.nan}, inplace=True)
            return df
        except Exception as e:
            raise NetworkSecurityException(e, sys)

    def export_data_into_feature_store(self, dataframe: pd.DataFrame) -> pd.DataFrame:
        try:
            feature_store_file_path = self.data_ingestion_config.feature_store_file_path
            dir_path = os.path.dirname(feature_store_file_path)
            os.makedirs(dir_path, exist_ok=True)
            
            dataframe.to_csv(feature_store_file_path, index=False, header=True)
            return dataframe
        except Exception as e:
            raise NetworkSecurityException(e, sys)

    def split_data_as_train_test(self, dataframe: pd.DataFrame) -> None:
        try:
            train_set, test_set = train_test_split(
                dataframe, 
                test_size=self.data_ingestion_config.train_test_split_ratio
            )
            logging.info("Performed train-test split on the dataframe.")
            logging.info(f"Train set size: {train_set.shape} | Test set size: {test_set.shape}")

            # Ensure directories exist for both target paths
            train_dir_path = os.path.dirname(self.data_ingestion_config.training_file_path)
            test_dir_path = os.path.dirname(self.data_ingestion_config.testing_file_path)
            os.makedirs(train_dir_path, exist_ok=True)
            os.makedirs(test_dir_path, exist_ok=True)

            logging.info(f"Saving train set to: {self.data_ingestion_config.training_file_path}")
            train_set.to_csv(self.data_ingestion_config.training_file_path, index=False, header=True)

            logging.info(f"Saving test set to: {self.data_ingestion_config.testing_file_path}")
            test_set.to_csv(self.data_ingestion_config.testing_file_path, index=False, header=True)
            
        except Exception as e:
            raise NetworkSecurityException(e, sys)

    def initiate_data_ingestion(self) -> DataIngestionArtifact:
        try:
            dataframe = self.export_collection_as_dataframe()
            dataframe = self.export_data_into_feature_store(dataframe=dataframe)
            self.split_data_as_train_test(dataframe=dataframe)

            data_ingestion_artifact = DataIngestionArtifact(
                trained_file_path=self.data_ingestion_config.training_file_path,
                test_file_path=self.data_ingestion_config.testing_file_path
            )
            return data_ingestion_artifact
        except Exception as e:
            raise NetworkSecurityException(e, sys)


# --- RUN DIRECTLY TO CHECK OUTPUT ---
if __name__ == "__main__":
    try:
        # 1. Setup configurations
        training_pipeline_config = TrainingPipelineConfig()
        data_ingestion_config = DataIngestionConfig(training_pipeline_config)
        
        # 2. Run ingestion
        data_ingestion = DataIngestion(data_ingestion_config)
        artifact = data_ingestion.initiate_data_ingestion()
        
        # 3. Print verification info
        print("\n" + "="*50)
        print("SUCCESS! Data Ingestion Artifact Created:")
        print("="*50)
        print(f"Train File Saved At : {artifact.trained_file_path}")
        print(f"Test File Saved At  : {artifact.test_file_path}")
        print("="*50 + "\n")
        
    except Exception as e:
        print(f"Execution Failed: {e}")