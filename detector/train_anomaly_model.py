from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest

from detector.dataset_builder import (
    load_events,
    build_feature_dataset
)
from detector.feature_extractor import FEATURE_NAMES


PROJECT_ROOT = Path(__file__).resolve().parent.parent

TRAINING_LOG_FILE = (
    PROJECT_ROOT
    / "data"
    / "normal_training_events.jsonl"
)

MODEL_DIRECTORY = PROJECT_ROOT / "models"

MODEL_FILE = (
    MODEL_DIRECTORY
    / "isolation_forest.joblib"
)

WINDOW_SIZE = 5


def train_anomaly_model():

    if not TRAINING_LOG_FILE.exists():
        raise FileNotFoundError(
            "Normal training data was not found. "
            "Run: python -m simulator.generate_training_data"
        )

    events = load_events(TRAINING_LOG_FILE)

    dataset = build_feature_dataset(
        events,
        window_size=WINDOW_SIZE
    )

    if len(dataset) < 50:
        raise ValueError(
            "At least 50 observation windows are required "
            "to train the anomaly model."
        )

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )

    model.fit(dataset)

    predictions = model.predict(dataset)
    anomaly_scores = model.decision_function(dataset)

    normal_windows = sum(
        prediction == 1
        for prediction in predictions
    )

    unusual_windows = sum(
        prediction == -1
        for prediction in predictions
    )

    model_package = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "window_size": WINDOW_SIZE
    }

    MODEL_DIRECTORY.mkdir(exist_ok=True)

    joblib.dump(
        model_package,
        MODEL_FILE
    )

    print(f"Training events: {len(events)}")
    print(f"Training windows: {len(dataset)}")
    print(f"Normal-like windows: {normal_windows}")
    print(f"Unusual training windows: {unusual_windows}")

    print(
        "Anomaly-score range: "
        f"{min(anomaly_scores):.4f} "
        f"to {max(anomaly_scores):.4f}"
    )

    print(f"Model saved to: {MODEL_FILE}")


if __name__ == "__main__":
    train_anomaly_model()