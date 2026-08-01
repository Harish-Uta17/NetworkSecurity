from pathlib import Path
from networksecurity.pipeline.batch_prediction import BatchPredictionPipeline

if __name__ == "__main__":
    # Initialize batch pipeline
    batch_pipeline = BatchPredictionPipeline()

    # Define input CSV path
    test_csv_path = Path("Network_Data/phisingData.csv")

    if test_csv_path.exists():
        # Run prediction on CSV
        predictions_df = batch_pipeline.predict_file(test_csv_path)
        print("Batch prediction successful! Sample output:")
        print(predictions_df.head())
    else:
        print(f"File not found at: {test_csv_path}")