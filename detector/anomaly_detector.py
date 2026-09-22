from pathlib import Path

import joblib

from detector.feature_extractor import (
    FEATURE_NAMES,
    extract_window_features,
    features_to_vector
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "isolation_forest.joblib"
)

_model_package = None


def load_anomaly_model():

    global _model_package

    if _model_package is not None:
        return _model_package

    if not MODEL_FILE.exists():
        raise FileNotFoundError(
            "Trained anomaly model was not found. "
            "Run: python -m detector.train_anomaly_model"
        )

    _model_package = joblib.load(MODEL_FILE)

    trained_feature_names = _model_package.get(
        "feature_names"
    )

    if trained_feature_names != FEATURE_NAMES:
        raise ValueError(
            "The model feature schema does not match "
            "the current feature extractor."
        )

    return _model_package


def analyze_window(events):

    if not events:
        return None

    model_package = load_anomaly_model()
    model = model_package["model"]

    features = extract_window_features(events)
    feature_vector = features_to_vector(features)

    prediction = model.predict(
        [feature_vector]
    )[0]

    anomaly_score = model.decision_function(
        [feature_vector]
    )[0]

    source_ips = sorted({
        event["source_ip"]
        for event in events
        if event.get("source_ip")
    })

    return {
        "is_anomaly": prediction == -1,
        "anomaly_score": round(
            float(anomaly_score),
            4
        ),
        "event_count": len(events),
        "source_ips": source_ips,
        "features": features
    }


def detect_anomaly(events):

    analysis = analyze_window(events)

    if analysis is None:
        return None

    if not analysis["is_anomaly"]:
        return None

    return {
        "attack_type": "ANOMALOUS_BEHAVIOR",
        "detection_method": "ISOLATION_FOREST",
        "severity": "MEDIUM",
        "anomaly_score": analysis["anomaly_score"],
        "event_count": analysis["event_count"],
        "source_ips": analysis["source_ips"],
        "features": analysis["features"]
    }