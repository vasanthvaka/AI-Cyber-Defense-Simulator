import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from config.settings import (
    DEFAULT_CONFIG_FILE,
    load_config,
    validate_config
)


class TestSecuritySettings(unittest.TestCase):

    def test_default_configuration_loads(self):

        config = load_config(
            force_reload=True
        )

        self.assertEqual(
            config["detectors"]
            ["brute_force"]
            ["attempt_threshold"],
            5
        )

        self.assertEqual(
            config["ai_window"]
            ["window_size_seconds"],
            5
        )

        self.assertEqual(
            config["simulation"]
            ["live_mode"]
            ["attack_probability"],
            0.35
        )

    def test_cached_configuration_is_protected(
        self
    ):

        first_config = load_config(
            force_reload=True
        )

        first_config["detectors"][
            "brute_force"
        ]["attempt_threshold"] = 999

        second_config = load_config()

        self.assertEqual(
            second_config["detectors"]
            ["brute_force"]
            ["attempt_threshold"],
            5
        )

    def test_missing_file_is_rejected(self):

        missing_file = (
            DEFAULT_CONFIG_FILE.parent
            / "missing-config.json"
        )

        with self.assertRaises(
            FileNotFoundError
        ):
            load_config(
                missing_file,
                force_reload=True
            )

    def test_invalid_json_is_rejected(self):

        with tempfile.TemporaryDirectory() as directory:

            config_file = (
                Path(directory)
                / "invalid.json"
            )

            with open(
                config_file,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(
                    "{ invalid json"
                )

            with self.assertRaises(
                ValueError
            ):
                load_config(
                    config_file,
                    force_reload=True
                )

    def test_invalid_range_is_rejected(self):

        config = deepcopy(
            load_config(
                force_reload=True
            )
        )

        normal_activity = (
            config["simulation"]
            ["normal_activity"]
        )

        normal_activity[
            "minimum_events"
        ] = 20

        normal_activity[
            "maximum_events"
        ] = 5

        with self.assertRaises(ValueError):
            validate_config(config)

    def test_configuration_file_round_trip(self):

        config = load_config(
            force_reload=True
        )

        with tempfile.TemporaryDirectory() as directory:

            config_file = (
                Path(directory)
                / "security_config.json"
            )

            with open(
                config_file,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    config,
                    file
                )

            loaded_config = load_config(
                config_file,
                force_reload=True
            )

        self.assertEqual(
            loaded_config,
            config
        )


if __name__ == "__main__":
    unittest.main()