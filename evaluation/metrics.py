import math


def _safe_divide(numerator, denominator):

    if denominator == 0:
        return 0.0

    return numerator / denominator


def calculate_classification_metrics(
    expected_labels,
    predicted_labels
):

    if not isinstance(expected_labels, list):
        raise TypeError(
            "Expected labels must be a list"
        )

    if not isinstance(predicted_labels, list):
        raise TypeError(
            "Predicted labels must be a list"
        )

    if not expected_labels:
        raise ValueError(
            "At least one evaluation result is required"
        )

    if len(expected_labels) != len(predicted_labels):
        raise ValueError(
            "Expected and predicted labels must "
            "have the same length"
        )

    valid_labels = {True, False, 1, 0}

    if any(
        label not in valid_labels
        for label in expected_labels
    ):
        raise ValueError(
            "Expected labels must be boolean values"
        )

    if any(
        label not in valid_labels
        for label in predicted_labels
    ):
        raise ValueError(
            "Predicted labels must be boolean values"
        )

    true_positives = 0
    false_positives = 0
    true_negatives = 0
    false_negatives = 0

    for expected, predicted in zip(
        expected_labels,
        predicted_labels
    ):

        expected = bool(expected)
        predicted = bool(predicted)

        if expected and predicted:
            true_positives += 1

        elif not expected and predicted:
            false_positives += 1

        elif not expected and not predicted:
            true_negatives += 1

        else:
            false_negatives += 1

    total = len(expected_labels)

    precision = _safe_divide(
        true_positives,
        true_positives + false_positives
    )

    recall = _safe_divide(
        true_positives,
        true_positives + false_negatives
    )

    false_positive_rate = _safe_divide(
        false_positives,
        false_positives + true_negatives
    )

    accuracy = _safe_divide(
        true_positives + true_negatives,
        total
    )

    f1_score = _safe_divide(
        2 * precision * recall,
        precision + recall
    )

    return {
        "total_samples": total,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "true_negatives": true_negatives,
        "false_negatives": false_negatives,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "detection_rate": recall,
        "false_positive_rate": false_positive_rate,
        "f1_score": f1_score
    }


def calculate_latency_metrics(latencies_ms):

    if not isinstance(latencies_ms, list):
        raise TypeError(
            "Latencies must be provided as a list"
        )

    if not latencies_ms:
        raise ValueError(
            "At least one latency value is required"
        )

    if any(
        not isinstance(value, (int, float))
        or isinstance(value, bool)
        for value in latencies_ms
    ):
        raise TypeError(
            "Every latency must be numeric"
        )

    if any(value < 0 for value in latencies_ms):
        raise ValueError(
            "Latency values cannot be negative"
        )

    sorted_latencies = sorted(latencies_ms)

    percentile_index = max(
        0,
        math.ceil(
            0.95 * len(sorted_latencies)
        ) - 1
    )

    return {
        "sample_count": len(sorted_latencies),
        "average_ms": (
            sum(sorted_latencies)
            / len(sorted_latencies)
        ),
        "minimum_ms": sorted_latencies[0],
        "maximum_ms": sorted_latencies[-1],
        "p95_ms": sorted_latencies[
            percentile_index
        ]
    }