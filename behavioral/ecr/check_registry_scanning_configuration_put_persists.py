"""registry-scanning-configuration-put-persists."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "registry-scanning-configuration-put-persists"
GROUP = "server-side"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-scanning")
def run(ctx) -> None:
    """PutRegistryScanningConfiguration with a BASIC SCAN_ON_PUSH rule echoes the filter, and
    GetRegistryScanningConfiguration returns the same scan type, frequency and filter."""
    ecr = ctx.client("ecr")

    original = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    ctx.on_cleanup(lambda: ecr.put_registry_scanning_configuration(**_as_put_kwargs(original)))

    probe_filter = ctx.unique_name("sim2real-orgpolicy-") + "*"
    probe_config = {
        "scanType": "BASIC",
        "rules": [
            {
                "scanFrequency": "SCAN_ON_PUSH",
                "repositoryFilters": [{"filter": probe_filter, "filterType": "WILDCARD"}],
            }
        ],
    }

    put_resp = ecr.put_registry_scanning_configuration(**_as_put_kwargs(probe_config))
    put_result = put_resp["registryScanningConfiguration"]
    assert put_result["scanType"] == "BASIC"
    assert put_result["rules"][0]["repositoryFilters"][0]["filter"] == probe_filter

    # Assert the resulting STATE, not just the mutation response: an independent
    # Get must reflect exactly what was just written.
    fetched = _poll_until_matches(ecr, probe_filter)
    assert fetched["scanType"] == "BASIC"
    assert fetched["rules"][0]["scanFrequency"] == "SCAN_ON_PUSH"
    assert fetched["rules"][0]["repositoryFilters"][0]["filter"] == probe_filter


def _as_put_kwargs(config):
    kwargs = {}
    if config.get("scanType") is not None:
        kwargs["scanType"] = config["scanType"]
    if config.get("rules") is not None:
        kwargs["rules"] = config["rules"]
    return kwargs


def _poll_until_matches(ecr, expected_filter, timeout_s=20.0, interval_s=1.0):
    """Poll GetRegistryScanningConfiguration until the just-written filter shows up
    (bounded wait for propagation), then return the observed configuration."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
        rules = last.get("rules") or []
        if any(
            f.get("filter") == expected_filter
            for r in rules
            for f in r.get("repositoryFilters", [])
        ):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"probe filter {expected_filter!r} never appeared: last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
