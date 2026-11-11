"""ec2-deep-inspection-configuration-activation-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ec2-deep-inspection-configuration-activation-transition"
GROUP = "state"
SERVICES = ["inspector2"]

_RESOURCE_TYPE = "EC2"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:inspector2")
def run(ctx) -> None:
    """UpdateEc2DeepInspectionConfiguration's packagePaths are persisted and status settles to a terminal value."""
    inspector2 = ctx.client("inspector2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # EC2 deep inspection configuration requires EC2 scanning to be enabled for the account.
    original_status = _resource_status(inspector2, account_id, _RESOURCE_TYPE)

    def _restore_enablement():
        if original_status == "ENABLED":
            inspector2.enable(resourceTypes=[_RESOURCE_TYPE])
        else:
            inspector2.disable(resourceTypes=[_RESOURCE_TYPE])

    ctx.on_cleanup(_restore_enablement)

    inspector2.enable(resourceTypes=[_RESOURCE_TYPE])
    _poll_until(
        lambda: _resource_status(inspector2, account_id, _RESOURCE_TYPE),
        lambda s: s == "ENABLED",
        timeout_s=120,
        interval_s=3,
    )

    original = inspector2.get_ec2_deep_inspection_configuration()
    original_paths = original.get("packagePaths", [])

    def _restore():
        inspector2.update_ec2_deep_inspection_configuration(packagePaths=original_paths)

    ctx.on_cleanup(_restore)

    new_path = f"/opt/{ctx.unique_name('sim2real-deep-inspection')}"
    updated = inspector2.update_ec2_deep_inspection_configuration(packagePaths=[new_path])
    assert updated["status"] in ("PENDING", "ACTIVATED"), f"unexpected status {updated['status']!r}"

    final_status = _poll_until(
        lambda: inspector2.get_ec2_deep_inspection_configuration(),
        lambda r: r["status"] in ("ACTIVATED", "DEACTIVATED", "FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    assert final_status["status"] == "ACTIVATED", (
        f"expected ACTIVATED after setting packagePaths, got {final_status['status']!r} "
        f"(errorMessage={final_status.get('errorMessage')!r})"
    )
    final_paths = final_status.get("packagePaths", [])
    assert new_path in final_paths, f"expected {new_path!r} in packagePaths, got {final_paths!r}"


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
