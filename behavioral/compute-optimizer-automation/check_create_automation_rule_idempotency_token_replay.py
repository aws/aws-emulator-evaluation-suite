"""create-automation-rule-idempotency-token-replay."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-automation-rule-idempotency-token-replay"
GROUP = "idempotency"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """Replaying CreateAutomationRule with the same clientToken and identical parameters is idempotent: no duplicate rule."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    token = ctx.unique_name("s2rtok-")
    name = ctx.unique_name("sim2real-rule-")
    kwargs = _rule_kwargs(name, status="Inactive")

    first = client.create_automation_rule(clientToken=token, **kwargs)
    rule_arn = first["ruleArn"]
    ctx.on_cleanup(lambda: _cleanup_rule(client, rule_arn))

    second = client.create_automation_rule(clientToken=token, **kwargs)

    assert second["ruleArn"] == first["ruleArn"], (
        f"replaying clientToken={token} must return the same ruleArn, "
        f"got {second['ruleArn']!r} vs original {first['ruleArn']!r}"
    )
    assert second["ruleId"] == first["ruleId"], (
        f"replaying clientToken={token} must return the same ruleId, "
        f"got {second['ruleId']!r} vs original {first['ruleId']!r}"
    )
    assert second["ruleRevision"] == first["ruleRevision"], (
        f"an idempotent replay must not advance the revision, "
        f"got {second['ruleRevision']!r} vs original {first['ruleRevision']!r}"
    )

    listed = client.list_automation_rules(filters=[{"name": "Name", "values": [name]}])[
        "automationRules"
    ]
    assert len(listed) == 1, (
        f"expected exactly one rule named {name!r} after the replayed create, found {len(listed)}"
    )


def _ensure_enrolled(ctx) -> None:
    co = ctx.client("compute-optimizer")
    base_status = co.get_enrollment_status().get("status")
    if base_status != "Active":
        co.update_enrollment_status(status="Active", includeMemberAccounts=False)
        # Not restored: an opt-out blocks opting back in for 24 hours.
        deadline0 = time.monotonic() + 120
        while time.monotonic() < deadline0:
            base_status = co.get_enrollment_status().get("status")
            if base_status == "Active":
                break
            if base_status == "Failed":
                raise AssertionError("compute-optimizer base enrollment failed")
            time.sleep(3)
        else:
            raise AssertionError(
                "compute-optimizer base enrollment did not reach Active within 120s",
            )

    client = ctx.client("compute-optimizer-automation")
    cfg = client.get_enrollment_configuration()
    if cfg["status"] == "Active":
        return
    if cfg["status"] in ("Inactive", "Pending", "Failed"):
        client.update_enrollment_configuration(status="Active")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        cfg = client.get_enrollment_configuration()
        if cfg["status"] == "Active":
            return
        if cfg["status"] == "Failed":
            raise AssertionError(f"account enrollment failed: {cfg.get('statusReason')}")
        time.sleep(2)
    raise AssertionError(
        "account did not reach Active Compute Optimizer Automation enrollment status "
        "within 60s of requesting UpdateEnrollmentConfiguration(status=Active)",
    )


def _rule_kwargs(name: str, status: str = "Inactive") -> dict:
    return {
        "name": name,
        "ruleType": "AccountRule",
        "recommendedActionTypes": ["SnapshotAndDeleteUnattachedEbsVolume"],
        "schedule": {
            "scheduleExpression": "cron(30 12 * * ? *)",
            "scheduleExpressionTimezone": "UTC",
            "executionWindowInMinutes": 60,
        },
        "status": status,
        "criteria": {
            "resourceArn": [
                {
                    "comparison": "StringEquals",
                    "values": ["arn:aws:ec2:us-east-1:111122223333:volume/vol-0000000000000dead"],
                }
            ]
        },
        "tags": [{"key": "sim2real-env", "value": "behavioral"}],
    }


def _cleanup_rule(client, rule_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        current = client.get_automation_rule(ruleArn=rule_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    try:
        client.delete_automation_rule(ruleArn=rule_arn, ruleRevision=current["ruleRevision"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
