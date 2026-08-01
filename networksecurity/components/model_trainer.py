import os
import json
import sys

from networksecurity.exception.exception import NetworkSecurityException 
from networksecurity.logging.logger import logging

from networksecurity.entity.artifact_entity import DataTransformationArtifact, ModelTrainerArtifact
from networksecurity.entity.config_entity import ModelTrainerConfig, TrainingPipelineConfig

from networksecurity.utils.ml_utils.model.estimator import NetworkModel
from networksecurity.utils.main_utils.utils import save_object, load_object
from networksecurity.utils.main_utils.utils import load_numpy_array_data, evaluate_models
from networksecurity.utils.ml_utils.metric.classification_metric import get_classification_score

from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, r2_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import (
    AdaBoostClassifier,
    GradientBoostingClassifier,
    RandomForestClassifier,
)
import mlflow
import dagshub

# Initialize DagsHub and MLflow safely
try:
    dagshub.init(repo_owner='Harish-Uta17', repo_name='NetworkSecurity', mlflow=True)
except Exception as e:
    logging.warning(f"Failed to initialize DagsHub: {e}")

tracking_uri = os.getenv("MLFLOW_TRACKING_URI")
if tracking_uri:
    mlflow.set_tracking_uri(tracking_uri)

experiment_name = os.getenv("MLFLOW_EXPERIMENT_NAME", "NetworkSecurity")
mlflow.set_experiment(experiment_name)


class ModelTrainer:
    def __init__(self, model_trainer_config: ModelTrainerConfig, data_transformation_artifact: DataTransformationArtifact):
        try:
            self.model_trainer_config = model_trainer_config
            self.data_transformation_artifact = data_transformation_artifact
        except Exception as e:
            raise NetworkSecurityException(e, sys)
        
    def track_mlflow(self, best_model, classificationmetric, metric_type="train"):
        """Logs classification metrics and trained model artifacts to MLflow safely."""
        f1_score = classificationmetric.f1_score
        precision_score = classificationmetric.precision_score
        recall_score = classificationmetric.recall_score

        try:
            with mlflow.start_run(run_name=f"Model_Evaluation_{metric_type}"):
                mlflow.log_metric(f"{metric_type}_f1_score", f1_score)
                mlflow.log_metric(f"{metric_type}_precision", precision_score)
                mlflow.log_metric(f"{metric_type}_recall_score", recall_score)
                mlflow.sklearn.log_model(best_model, "model")
        except Exception as e:
            logging.warning(f"MLflow tracking failed: {e}. Skipping MLflow logging.")

    def train_model(self, X_train, y_train, x_test, y_test):
        try:
            # FIX 1 & 2: Wrapped Logistic Regression in a Pipeline with StandardScaler,
            # removed deprecated n_jobs=-1, and set max_iter=1000 for clean convergence.
            models = {
                # Keep the serialized forest small enough for Streamlit Cloud.
                "Random Forest": RandomForestClassifier(n_jobs=1, verbose=1),
                "Decision Tree": DecisionTreeClassifier(),
                "Gradient Boosting": GradientBoostingClassifier(verbose=1),
                "Logistic Regression": make_pipeline(
                    StandardScaler(),
                    LogisticRegression(max_iter=1000, verbose=1)
                ),
                "AdaBoost": AdaBoostClassifier(),
            }
            
            # Streamlined hyperparameter grids
            params = {
                "Decision Tree": {
                    'criterion': ['gini', 'entropy'],
                    'max_depth': [10, 20],
                    'min_samples_leaf': [20],
                },
                "Random Forest": {
                    'n_estimators': [64],
                    'max_depth': [20, 25],
                    'min_samples_leaf': [20],
                    'max_features': ['sqrt'],
                },
                "Gradient Boosting": {
                    'learning_rate': [0.1],
                    'subsample': [0.8],
                    'n_estimators': [64],
                    'max_depth': [3],
                },
                "Logistic Regression": {},
                "AdaBoost": {
                    'learning_rate': [0.1],
                    'n_estimators': [64]
                }
            }
            
            # Evaluate models across hyperparameters
            model_report: dict = evaluate_models(
                X_train=X_train, y_train=y_train, X_test=x_test, y_test=y_test,
                models=models, param=params
            )
            
            # Extract score and name of the best performing model
            best_model_score = max(sorted(model_report.values()))

            best_model_name = list(model_report.keys())[
                list(model_report.values()).index(best_model_score)
            ]
            
            # Retrieve the fitted model object
            best_model = models[best_model_name]

            # Enforce expected accuracy threshold safety check
            expected_score = getattr(self.model_trainer_config, "expected_accuracy", 0.6)
            if best_model_score < expected_score:
                raise Exception(f"No best model found with score greater than expected threshold: {expected_score}")
            
            logging.info(f"Best found model: {best_model_name} with test evaluation score: {best_model_score}")

            # Refit best model on X_train to ensure it is fully trained with top hyperparams
            best_model.fit(X_train, y_train)

            # Calculate train metric scores & log to MLflow
            y_train_pred = best_model.predict(X_train)
            classification_train_metric = get_classification_score(y_true=y_train, y_pred=y_train_pred)
            self.track_mlflow(best_model, classification_train_metric, metric_type="train")

            # Calculate test metric scores & log to MLflow
            y_test_pred = best_model.predict(x_test)
            classification_test_metric = get_classification_score(y_true=y_test, y_pred=y_test_pred)
            self.track_mlflow(best_model, classification_test_metric, metric_type="test")

            tn, fp, fn, tp = confusion_matrix(y_test, y_test_pred).ravel()
            deployment_metrics = {
                "accuracy": float(accuracy_score(y_test, y_test_pred)),
                "precision": float(classification_test_metric.precision_score),
                "recall": float(classification_test_metric.recall_score),
                "f1_score": float(classification_test_metric.f1_score),
                "true_negative": float(tn),
                "false_positive": float(fp),
                "false_negative": float(fn),
                "true_positive": float(tp),
            }

            # Load fitted preprocessor pipeline object
            preprocessor = load_object(file_path=self.data_transformation_artifact.transformed_object_file_path)
            
            model_dir_path = os.path.dirname(self.model_trainer_config.trained_model_file_path)
            os.makedirs(model_dir_path, exist_ok=True)

            # Package preprocessor and best model into single NetworkModel object
            Network_Model = NetworkModel(preprocessor=preprocessor, model=best_model)
            
            # Save packaged model into training pipeline artifacts directory
            save_object(self.model_trainer_config.trained_model_file_path, obj=Network_Model)
            
            # Save packaged model to final deployment folder
            os.makedirs("final_model", exist_ok=True)
            save_object("final_model/model.pkl", obj=Network_Model)
            with open("final_model/metrics.json", "w", encoding="utf-8") as metrics_file:
                json.dump(deployment_metrics, metrics_file, indent=2)

            # Construct Model Trainer Artifact
            model_trainer_artifact = ModelTrainerArtifact(
                trained_model_file_path=self.model_trainer_config.trained_model_file_path,
                train_metric_artifact=classification_train_metric,
                test_metric_artifact=classification_test_metric
            )
            logging.info(f"Model trainer artifact created: {model_trainer_artifact}")
            return model_trainer_artifact

        except Exception as e:
            raise NetworkSecurityException(e, sys)

    def initiate_model_trainer(self) -> ModelTrainerArtifact:
        try:
            train_file_path = self.data_transformation_artifact.transformed_train_file_path
            test_file_path = self.data_transformation_artifact.transformed_test_file_path

            # Load preprocessed arrays
            train_arr = load_numpy_array_data(train_file_path)
            test_arr = load_numpy_array_data(test_file_path)

            x_train, y_train, x_test, y_test = (
                train_arr[:, :-1],
                train_arr[:, -1],
                test_arr[:, :-1],
                test_arr[:, -1],
            )

            model_trainer_artifact = self.train_model(x_train, y_train, x_test, y_test)
            return model_trainer_artifact

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
        
        transformed_train_path = os.path.join(latest_artifact_dir, "data_transformation", "transformed", "train.npy")
        transformed_test_path = os.path.join(latest_artifact_dir, "data_transformation", "transformed", "test.npy")
        transformed_object_path = os.path.join(latest_artifact_dir, "data_transformation", "transformed_object", "preprocessing.pkl")

        print(f"Using latest transformed data from: {latest_artifact_dir}")

        # Mock DataTransformationArtifact
        data_transformation_artifact = DataTransformationArtifact(
            transformed_object_file_path=transformed_object_path,
            transformed_train_file_path=transformed_train_path,
            transformed_test_file_path=transformed_test_path
        )

        # Initialize Configs & Class
        training_pipeline_config = TrainingPipelineConfig()
        model_trainer_config = ModelTrainerConfig(training_pipeline_config=training_pipeline_config)

        model_trainer = ModelTrainer(
            model_trainer_config=model_trainer_config,
            data_transformation_artifact=data_transformation_artifact
        )

        # Trigger Model Training
        print("Starting Model Trainer execution...")
        trainer_artifact = model_trainer.initiate_model_trainer()
        
        print("\n--- Model Trainer Completed Successfully! ---")
        print(f"Trained Model Path : {trainer_artifact.trained_model_file_path}")
        print(f"Train Metrics      : {trainer_artifact.train_metric_artifact}")
        print(f"Test Metrics       : {trainer_artifact.test_metric_artifact}")

    except Exception as e:
        raise NetworkSecurityException(e, sys)
