import unittest

from evaluation.metrics import (
    calculate_classification_metrics,
    calculate_latency_metrics
)


class TestEvaluationMetrics(unittest.TestCase):

    def test_perfect_classification(self):

        metrics = calculate_classification_metrics(
            [True, True, False, False],
            [True, True, False, False]
        )

        self.assertEqual(
            metrics["true_positives"],
            2
        )

        self.assertEqual(
            metrics["true_negatives"],
            2
        )

        self.assertEqual(
            metrics["accuracy"],
            1.0
        )

        self.assertEqual(
            metrics["f1_score"],
            1.0
        )

    def test_mixed_classification(self):

        metrics = calculate_classification_metrics(
            [True, True, False, False],
            [True, False, True, False]
        )

        self.assertEqual(
            metrics["true_positives"],
            1
        )

        self.assertEqual(
            metrics["false_negatives"],
            1
        )

        self.assertEqual(
            metrics["false_positives"],
            1
        )

        self.assertEqual(
            metrics["true_negatives"],
            1
        )

        self.assertEqual(
            metrics["accuracy"],
            0.5
        )

        self.assertEqual(
            metrics["false_positive_rate"],
            0.5
        )

    def test_zero_denominators_are_safe(self):

        metrics = calculate_classification_metrics(
            [False, False],
            [False, False]
        )

        self.assertEqual(
            metrics["precision"],
            0.0
        )

        self.assertEqual(
            metrics["recall"],
            0.0
        )

    def test_mismatched_labels_are_rejected(self):

        with self.assertRaises(ValueError):
            calculate_classification_metrics(
                [True, False],
                [True]
            )

    def test_latency_metrics(self):

        metrics = calculate_latency_metrics(
            [10.0, 20.0, 30.0, 40.0]
        )

        self.assertEqual(
            metrics["sample_count"],
            4
        )

        self.assertEqual(
            metrics["average_ms"],
            25.0
        )

        self.assertEqual(
            metrics["minimum_ms"],
            10.0
        )

        self.assertEqual(
            metrics["maximum_ms"],
            40.0
        )

        self.assertEqual(
            metrics["p95_ms"],
            40.0
        )


if __name__ == "__main__":
    unittest.main()