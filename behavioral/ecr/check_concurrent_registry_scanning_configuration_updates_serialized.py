"""concurrent-registry-scanning-configuration-updates-serialized."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-registry-scanning-configuration-updates-serialized"
GROUP = "concurrency"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-scanning")
def run(ctx) -> None:
    """Two concurrent PutRegistryScanningConfiguration calls with different, mutually
    incompatible rule sets resolve deterministically to exactly one complete winner --
    never a partial merge of scanType from one call with rules from the other."""
    ecr = ctx.client("ecr")

    original = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    ctx.on_cleanup(lambda: ecr.put_registry_scanning_configuration(**_as_put_kwargs(original)))

    filter_a = ctx.unique_name("sim2real-cc-a-") + "*"
    filter_b = ctx.unique_name("sim2real-cc-b-") + "*"

    config_a = {
        "scanType": "BASIC",
        "rules": [
            {
                "scanFrequency": "SCAN_ON_PUSH",
                "repositoryFilters": [{"filter": filter_a, "filterType": "WILDCARD"}],
            }
        ],
    }
    config_b = {
        "scanType": "ENHANCED",
        "rules": [
            {
                "scanFrequency": "CONTINUOUS_SCAN",
                "repositoryFilters": [{"filter": filter_b, "filterType": "WILDCARD"}],
            }
        ],
    }

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(ecr.put_registry_scanning_configuration, **_as_put_kwargs(config_a))
        fut_b = pool.submit(ecr.put_registry_scanning_configuration, **_as_put_kwargs(config_b))
        fut_a.result()
        fut_b.result()

    observed = _poll_until_stable(ecr)

    is_a = _configs_equal(observed, config_a)
    is_b = _configs_equal(observed, config_b)
    assert is_a != is_b, (
        f"expected exactly one complete winner (A xor B), got scanType="
        f"{observed.get('scanType')} rules={observed.get('rules')}"
    )


def _as_put_kwargs(config):
    kwargs = {}
    if config.get("scanType") is not None:
        kwargs["scanType"] = config["scanType"]
    if config.get("rules") is not None:
        kwargs["rules"] = config["rules"]
    return kwargs


def _configs_equal(observed, expected):
    if observed.get("scanType") != expected.get("scanType"):
        return False
    obs_rules = observed.get("rules") or []
    exp_rules = expected.get("rules") or []
    if len(obs_rules) != len(exp_rules):
        return False
    for exp_rule in exp_rules:
        match = any(
            r.get("scanFrequency") == exp_rule["scanFrequency"]
            and r.get("repositoryFilters") == exp_rule["repositoryFilters"]
            for r in obs_rules
        )
        if not match:
            return False
    return True


def _poll_until_stable(ecr, timeout_s=20.0, interval_s=1.0):
    """Poll GetRegistryScanningConfiguration until two consecutive reads agree, to
    absorb any eventual-consistency propagation delay after the two concurrent writes."""
    deadline = time.monotonic() + timeout_s
    previous = None
    while time.monotonic() < deadline:
        current = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
        if previous is not None and current == previous:
            return current
        previous = current
        time.sleep(interval_s)
    raise AssertionError(
        f"registry scanning configuration never stabilized within {timeout_s}s after the "
        f"concurrent puts -- last observed scanType={previous.get('scanType') if previous else None} "
        f"rules={previous.get('rules') if previous else None}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
