import os
import sys
import json
import certifi
import pandas as pd
import numpy as np
import pymongo
from dotenv import load_dotenv

from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging

load_dotenv()

MONGO_DB_URL = os.getenv("MONGO_DB_URL")
ca = certifi.where()

class NetworkDataExtract():
    def __init__(self):
        try:
            pass
        except Exception as e:
            raise NetworkSecurityException(e, sys)
        
    def csv_to_json_convertor(self, file_path):
        try:
            logging.info(f"Reading CSV file from path: {file_path}")
            data = pd.read_csv(file_path)
            data.reset_index(drop=True, inplace=True)
            records = list(json.loads(data.T.to_json()).values())
            logging.info(f"Successfully converted {len(records)} rows to JSON format.")
            return records
        except Exception as e:
            raise NetworkSecurityException(e, sys)
        
    def insert_data_mongodb(self, records, database, collection_name):
        try:
            if not MONGO_DB_URL:
                raise Exception("MONGO_DB_URL is not set. Please set it in your .env file")
            
            # Connect to MongoDB Atlas
            self.mongo_client = pymongo.MongoClient(MONGO_DB_URL, tls=True, tlsCAFile=ca)
            self.database = self.mongo_client[database]
            self.collection = self.database[collection_name]
            
            # CLEAR OLD IMBALANCED DATASET FIRST
            logging.info(f"Clearing old collection: {collection_name}")
            self.collection.drop()
            
            # BATCH INSERTION (Prevents connection timeouts on 242k rows)
            batch_size = 50000
            total_records = len(records)
            logging.info(f"Inserting {total_records} records in batches of {batch_size}...")

            for i in range(0, total_records, batch_size):
                batch = records[i : i + batch_size]
                self.collection.insert_many(batch)
                print(f"Uploaded batch {i // batch_size + 1} ({len(batch)} records)...")

            logging.info("MongoDB insertion completed successfully!")
            return total_records

        except Exception as e:
            raise NetworkSecurityException(e, sys)
        
if __name__ == '__main__':
    # Fix 1: Use forward slash for path compatibility
    FILE_PATH = "Network_Data/balanced_dataset.csv"
    DATABASE = "Database"
    COLLECTION = "NetworkData"
    
    networkobj = NetworkDataExtract()
    
    print("Converting CSV to JSON records...")
    records = networkobj.csv_to_json_convertor(file_path=FILE_PATH)
    
    print("Pushing data to MongoDB Atlas...")
    no_of_records = networkobj.insert_data_mongodb(records, DATABASE, COLLECTION)
    print(f"Done! Successfully inserted {no_of_records} records into MongoDB.")