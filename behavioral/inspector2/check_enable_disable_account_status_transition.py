"""enable-disable-account-status-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "enable-disable-account-status-transition"
GROUP = "state"
SERVICES = ["inspector2"]

_RESOURCE_TYPE = "LAMBDA_CODE"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:inspector2")
def run(ctx) -> None:
    """Enable/Disable drive Status through ENABLING->ENABLED and DISABLING->DISABLED for a resource type."""
    inspector2 = ctx.client("inspector2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    original_status = _resource_status(inspector2, account_id, _RESOURCE_TYPE)

    def _restore():
        if original_status == "ENABLED":
            inspector2.enable(resourceTypes=[_RESOURCE_TYPE])
        else:
            inspector2.disable(resourceTypes=[_RESOURCE_TYPE])

    ctx.on_cleanup(_restore)

    inspector2.enable(resourceTypes=[_RESOURCE_TYPE])
    enabled_status = _poll_until(
        lambda: _resource_status(inspector2, account_id, _RESOURCE_TYPE),
        lambda s: s == "ENABLED",
        timeout_s=120,
        interval_s=3,
    )
    assert enabled_status == "ENABLED", f"expected ENABLED, got {enabled_status}"

    inspector2.disable(resourceTypes=[_RESOURCE_TYPE])
    disabled_status = _poll_until(
        lambda: _resource_status(inspector2, account_id, _RESOURCE_TYPE),
        lambda s: s == "DISABLED",
        timeout_s=120,
        interval_s=3,
    )
    assert disabled_status == "DISABLED", f"expected DISABLED, got {disabled_status}"


def _resource_status(inspector2, account_id: str, resource_type: str) -> str:
    resp = inspector2.batch_get_account_status(accountIds=[account_id])
    accounts = resp["accounts"]
    assert len(accounts) == 1, f"expected exactly one account in response, got {len(accounts)}"
    resource_state = accounts[0]["resourceState"]
    key = "lambdaCode" if resource_type == "LAMBDA_CODE" else resource_type.lower()
    return resource_state[key]["status"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={value!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
