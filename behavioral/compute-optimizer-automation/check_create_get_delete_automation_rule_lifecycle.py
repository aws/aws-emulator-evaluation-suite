"""create-get-delete-automation-rule-lifecycle."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-get-delete-automation-rule-lifecycle"
GROUP = "lifecycle"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """CreateAutomationRule -> GetAutomationRule reflects all input fields -> DeleteAutomationRule removes it."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    name = ctx.unique_name("sim2real-rule-")
    created = client.create_automation_rule(**_rule_kwargs(name, status="Inactive"))
    rule_arn = created["ruleArn"]
    ctx.on_cleanup(lambda: _cleanup_rule(client, rule_arn))

    assert created["name"] == name, f"expected created name {name!r}, got {created['name']!r}"
    assert created["status"] == "Inactive", (
        f"expected created status Inactive, got {created['status']!r}"
    )
    assert created["ruleType"] == "AccountRule", (
        f"expected created ruleType AccountRule, got {created['ruleType']!r}"
    )
    assert created["recommendedActionTypes"] == ["SnapshotAndDeleteUnattachedEbsVolume"], (
        f"expected created recommendedActionTypes [SnapshotAndDeleteUnattachedEbsVolume], "
        f"got {created['recommendedActionTypes']!r}"
    )

    fetched = client.get_automation_rule(ruleArn=rule_arn)
    assert fetched["ruleArn"] == rule_arn, f"expected fetched ruleArn {rule_arn!r}, got {fetched['ruleArn']!r}"
    assert fetched["name"] == name, f"expected fetched name {name!r}, got {fetched['name']!r}"
    assert fetched["status"] == "Inactive", (
        f"expected fetched status Inactive, got {fetched['status']!r}"
    )
    assert fetched["ruleRevision"] == created["ruleRevision"], (
        f"expected fetched ruleRevision {created['ruleRevision']!r} to match creation, "
        f"got {fetched['ruleRevision']!r}"
    )

    client.delete_automation_rule(ruleArn=rule_arn, ruleRevision=fetched["ruleRevision"])

    code, message = _client_error(lambda: client.get_automation_rule(ruleArn=rule_arn))
    assert code == "ResourceNotFoundException", (
        f"expected GetAutomationRule on a deleted rule to raise ResourceNotFoundException, got {code!r}"
    )
    assert message == "The specified resource could not be found", (
        f"unexpected not-found message: {message!r}"
    )


# ===== helpers =====
def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, so an
    over-permissive target that accepts a call real AWS refuses never reads as a code
    mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _ensure_enrolled(ctx) -> None:
    

    co = ctx.client("compute-optimizer")
    base_status = co.get_enrollment_status().get("status")
    if base_status != "Active":
        co.update_enrollment_status(status="Active", includeMemberAccounts=False)
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
        # Restrictive, never-matching criteria: even an Active rule created by this
        # check can never actually implement an action against a real resource.
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
