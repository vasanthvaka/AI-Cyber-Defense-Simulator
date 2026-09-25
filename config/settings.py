import json
from copy import deepcopy
from pathlib import Path


PROJECT_ROOT = (
    Path(__file__).resolve().parent.parent
)

DEFAULT_CONFIG_FILE = (
    PROJECT_ROOT
    / "config"
    / "security_config.json"
)

_config_cache = None
_cached_file = None


def _require_dictionary(
    container,
    key,
    location
):

    value = container.get(key)

    if not isinstance(value, dict):
        raise ValueError(
            f"Configuration section "
            f"'{location}.{key}' must be "
            "a dictionary"
        )

    return value


def _require_number(
    container,
    key,
    location,
    minimum=None,
    maximum=None
):

    value = container.get(key)

    if (
        not isinstance(value, (int, float))
        or isinstance(value, bool)
    ):
        raise ValueError(
            f"Configuration value "
            f"'{location}.{key}' must be numeric"
        )

    if (
        minimum is not None
        and value < minimum
    ):
        raise ValueError(
            f"Configuration value "
            f"'{location}.{key}' must be at "
            f"least {minimum}"
        )

    if (
        maximum is not None
        and value > maximum
    ):
        raise ValueError(
            f"Configuration value "
            f"'{location}.{key}' must not exceed "
            f"{maximum}"
        )

    return value


def _validate_range(
    section,
    minimum_key,
    maximum_key,
    location,
    minimum_allowed=0
):

    minimum_value = _require_number(
        section,
        minimum_key,
        location,
        minimum=minimum_allowed
    )

    maximum_value = _require_number(
        section,
        maximum_key,
        location,
        minimum=minimum_allowed
    )

    if minimum_value > maximum_value:
        raise ValueError(
            f"Configuration range in "
            f"'{location}' is invalid: "
            f"{minimum_key} cannot exceed "
            f"{maximum_key}"
        )


def validate_config(config):

    if not isinstance(config, dict):
        raise ValueError(
            "Security configuration must be "
            "a dictionary"
        )

    detectors = _require_dictionary(
        config,
        "detectors",
        "config"
    )

    brute_force = _require_dictionary(
        detectors,
        "brute_force",
        "config.detectors"
    )

    for key in [
        "attempt_threshold",
        "time_window_seconds",
        "distributed_ip_threshold",
        "alert_cooldown_seconds"
    ]:
        _require_number(
            brute_force,
            key,
            "config.detectors.brute_force",
            minimum=1
        )

    ddos = _require_dictionary(
        detectors,
        "ddos",
        "config.detectors"
    )

    for key in [
        "request_threshold",
        "unique_ip_threshold",
        "time_window_seconds",
        "alert_cooldown_seconds"
    ]:
        _require_number(
            ddos,
            key,
            "config.detectors.ddos",
            minimum=1
        )

    port_scan = _require_dictionary(
        detectors,
        "port_scan",
        "config.detectors"
    )

    for key in [
        "port_threshold",
        "time_window_seconds",
        "alert_cooldown_seconds"
    ]:
        _require_number(
            port_scan,
            key,
            "config.detectors.port_scan",
            minimum=1
        )

    suspicious_process = _require_dictionary(
        detectors,
        "suspicious_process",
        "config.detectors"
    )

    _require_number(
        suspicious_process,
        "risk_threshold",
        "config.detectors.suspicious_process",
        minimum=1
    )

    ai_window = _require_dictionary(
        config,
        "ai_window",
        "config"
    )

    _require_number(
        ai_window,
        "window_size_seconds",
        "config.ai_window",
        minimum=1
    )

    _require_number(
        ai_window,
        "minimum_flush_events",
        "config.ai_window",
        minimum=1
    )

    simulation = _require_dictionary(
        config,
        "simulation",
        "config"
    )

    normal_activity = _require_dictionary(
        simulation,
        "normal_activity",
        "config.simulation"
    )

    _validate_range(
        normal_activity,
        "minimum_events",
        "maximum_events",
        "config.simulation.normal_activity",
        minimum_allowed=1
    )

    _validate_range(
        normal_activity,
        "minimum_delay_seconds",
        "maximum_delay_seconds",
        "config.simulation.normal_activity"
    )

    distributed = _require_dictionary(
        simulation,
        "distributed_brute_force",
        "config.simulation"
    )

    _validate_range(
        distributed,
        "minimum_attempts",
        "maximum_attempts",
        (
            "config.simulation."
            "distributed_brute_force"
        ),
        minimum_allowed=1
    )

    _validate_range(
        distributed,
        "minimum_source_ips",
        "maximum_source_ips",
        (
            "config.simulation."
            "distributed_brute_force"
        ),
        minimum_allowed=1
    )

    _require_number(
        distributed,
        "delay_seconds",
        (
            "config.simulation."
            "distributed_brute_force"
        ),
        minimum=0
    )

    ddos_simulation = _require_dictionary(
        simulation,
        "ddos",
        "config.simulation"
    )

    _validate_range(
        ddos_simulation,
        "minimum_requests",
        "maximum_requests",
        "config.simulation.ddos",
        minimum_allowed=1
    )

    _validate_range(
        ddos_simulation,
        "minimum_source_ips",
        "maximum_source_ips",
        "config.simulation.ddos",
        minimum_allowed=1
    )

    _require_number(
        ddos_simulation,
        "delay_seconds",
        "config.simulation.ddos",
        minimum=0
    )

    port_scan_simulation = _require_dictionary(
        simulation,
        "port_scan",
        "config.simulation"
    )

    _validate_range(
        port_scan_simulation,
        "minimum_ports",
        "maximum_ports",
        "config.simulation.port_scan",
        minimum_allowed=1
    )

    _require_number(
        port_scan_simulation,
        "delay_seconds",
        "config.simulation.port_scan",
        minimum=0
    )

    process_simulation = _require_dictionary(
        simulation,
        "suspicious_process",
        "config.simulation"
    )

    _validate_range(
        process_simulation,
        "minimum_events",
        "maximum_events",
        (
            "config.simulation."
            "suspicious_process"
        ),
        minimum_allowed=1
    )

    _require_number(
        process_simulation,
        "delay_seconds",
        (
            "config.simulation."
            "suspicious_process"
        ),
        minimum=0
    )

    live_mode = _require_dictionary(
        simulation,
        "live_mode",
        "config.simulation"
    )

    _require_number(
        live_mode,
        "attack_probability",
        "config.simulation.live_mode",
        minimum=0,
        maximum=1
    )

    _validate_range(
        live_mode,
        "minimum_normal_batches",
        "maximum_normal_batches",
        "config.simulation.live_mode",
        minimum_allowed=1
    )

    return True


def load_config(
    config_file=None,
    force_reload=False
):

    global _config_cache
    global _cached_file

    selected_file = Path(
        config_file
        if config_file is not None
        else DEFAULT_CONFIG_FILE
    ).resolve()

    if (
        not force_reload
        and _config_cache is not None
        and _cached_file == selected_file
    ):
        return deepcopy(_config_cache)

    if not selected_file.exists():
        raise FileNotFoundError(
            "Security configuration file "
            f"was not found: {selected_file}"
        )

    try:

        with open(
            selected_file,
            "r",
            encoding="utf-8"
        ) as file:

            config = json.load(file)

    except json.JSONDecodeError as error:

        raise ValueError(
            "Security configuration contains "
            f"invalid JSON: {error}"
        ) from error

    validate_config(config)

    _config_cache = config
    _cached_file = selected_file

    return deepcopy(config)


def get_config():

    return load_config()