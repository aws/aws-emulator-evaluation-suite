"""update-configuration-ecr-rescan-duration-persists."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-configuration-ecr-rescan-duration-persists"
GROUP = "state"
SERVICES = ["inspector2"]

_RESOURCE_TYPE = "ECR"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:inspector2", "resource:account-singleton:inspector2-configuration")
def run(ctx) -> None:
    """UpdateConfiguration's ecrConfiguration.rescanDuration is durably persisted and readable via GetConfiguration."""
    inspector2 = ctx.client("inspector2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # ECR rescan configuration requires ECR scanning to be enabled for the account.
    original_enable_status = _resource_status(inspector2, account_id, _RESOURCE_TYPE)

    def _restore_enablement():
        if original_enable_status == "ENABLED":
            inspector2.enable(resourceTypes=[_RESOURCE_TYPE])
        else:
            inspector2.disable(resourceTypes=[_RESOURCE_TYPE])

    ctx.on_cleanup(_restore_enablement)

    inspector2.enable(resourceTypes=[_RESOURCE_TYPE])
    _poll_until(
        lambda: _resource_status(inspector2, account_id, _RESOURCE_TYPE),
        lambda s: s in ("ENABLED", "ENABLING"),
        timeout_s=120,
        interval_s=3,
    )

    original = _retry_while_not_enabled(lambda: inspector2.get_configuration())
    original_duration = original.get("ecrConfiguration", {}).get("rescanDurationState", {}).get(
        "rescanDuration", "LIFETIME"
    )

    def _restore():
        inspector2.update_configuration(ecrConfiguration={"rescanDuration": original_duration})

    ctx.on_cleanup(_restore)

    new_duration = "DAYS_30" if original_duration != "DAYS_30" else "DAYS_90"
    _retry_while_not_enabled(
        lambda: inspector2.update_configuration(ecrConfiguration={"rescanDuration": new_duration})
    )

    got_duration = _poll_until(
        lambda: inspector2.get_configuration()["ecrConfiguration"]["rescanDurationState"]["rescanDuration"],
        lambda d: d == new_duration,
        timeout_s=60,
        interval_s=3,
    )
    assert got_duration == new_duration, f"expected {new_duration}, got {got_duration}"

    # Change it again to a different value to confirm it's a live setting, not a fixed stub value.
    third_duration = "DAYS_180" if new_duration != "DAYS_180" else "DAYS_60"
    _retry_while_not_enabled(
        lambda: inspector2.update_configuration(ecrConfiguration={"rescanDuration": third_duration})
    )
    got2_duration = _poll_until(
        lambda: inspector2.get_configuration()["ecrConfiguration"]["rescanDurationState"]["rescanDuration"],
        lambda d: d == third_duration,
        timeout_s=120,
        interval_s=5,
    )
    assert got2_duration == third_duration, f"expected {third_duration}, got {got2_duration}"


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


def _retry_while_not_enabled(fn, *, timeout_s: float = 90, interval_s: float = 5):
    """Retry fn() while ECR scanning is still transitioning (contention with other concurrently
    running checks that also toggle account-level ECR enablement can transiently flip it back)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            msg = e.response["Error"].get("Message", "")
            if "not enabled" in msg.lower():
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"operation never succeeded within {timeout_s}s while ECR enablement settled: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
