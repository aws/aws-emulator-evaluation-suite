"""batch-get-free-trial-info-returns-status-for-caller-account."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-get-free-trial-info-returns-status-for-caller-account"
GROUP = "state"
SERVICES = ["inspector2"]

_RESOURCE_TYPE = "EC2"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:inspector2")
def run(ctx) -> None:
    """BatchGetFreeTrialInfo returns per-scan-type free trial status entries for the caller's own
    account once at least one resource type has been enabled."""
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
    _poll_until(
        lambda: _resource_status(inspector2, account_id, _RESOURCE_TYPE),
        lambda s: s == "ENABLED",
        timeout_s=120,
        interval_s=3,
    )

    resp = inspector2.batch_get_free_trial_info(accountIds=[account_id])

    failed_ids = {f["accountId"] for f in resp.get("failedAccounts", [])}
    assert account_id not in failed_ids, f"caller account unexpectedly present in failedAccounts: {resp['failedAccounts']}"

    accounts = resp["accounts"]
    matching = [a for a in accounts if a["accountId"] == account_id]
    assert len(matching) == 1, f"expected exactly one entry for {account_id}, got {len(matching)}"

    info_list = matching[0]["freeTrialInfo"]
    assert len(info_list) > 0, "expected at least one freeTrialInfo entry once EC2 scanning is enabled"
    ec2_entries = [e for e in info_list if e["type"] == _RESOURCE_TYPE]
    assert len(ec2_entries) == 1, (
        f"expected exactly one {_RESOURCE_TYPE} freeTrialInfo entry after enabling it, "
        f"got {len(ec2_entries)}: {info_list}"
    )
    for entry in info_list:
        assert entry["status"] in ("ACTIVE", "INACTIVE"), f"unexpected FreeTrialStatus {entry['status']!r}"
        assert entry["type"] in (
            "EC2",
            "ECR",
            "LAMBDA",
            "LAMBDA_CODE",
            "CODE_REPOSITORY",
            "VM",
            "CONTAINER_IMAGE",
            "SERVERLESS_FUNCTION",
        ), f"unexpected FreeTrialType {entry['type']!r}"
        assert entry["end"] > entry["start"], "free trial end time must be after its start time"


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

