"""update-automation-rule-stale-revision-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-automation-rule-stale-revision-rejected"
GROUP = "overly-permissive"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """A second UpdateAutomationRule reusing an already-superseded ruleRevision is rejected with
    InvalidParameterValueException (optimistic-lock conflict) and never applied."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    name = ctx.unique_name("sim2real-rule-")
    created = client.create_automation_rule(**_rule_kwargs(name, status="Inactive"))
    rule_arn = created["ruleArn"]
    ctx.on_cleanup(lambda: _cleanup_rule(client, rule_arn))
    stale_revision = created["ruleRevision"]

    first_update = client.update_automation_rule(
        ruleArn=rule_arn,
        ruleRevision=stale_revision,
        description="legit-update",
    )
    current_revision = first_update["ruleRevision"]
    assert current_revision > stale_revision, (
        f"expected revision to advance past {stale_revision!r}, got {current_revision!r}"
    )

    # Break exactly one thing: reuse the now-stale revision for a second update.
    code, message = _error_code(
        lambda: client.update_automation_rule(
            ruleArn=rule_arn,
            ruleRevision=stale_revision,
            description="should-never-apply",
        )
    )
    assert code == "InvalidParameterValueException", f"unexpected code: {code!r}"
    assert message == (
        f"Rule revision does not match the current revision number {current_revision}"
    ), f"unexpected stale-revision message: {message!r}"

    # Effect absent: the rejected update must not have overwritten the legit description.
    fetched = client.get_automation_rule(ruleArn=rule_arn)
    assert fetched["description"] == "legit-update", (
        f"expected 'legit-update', got {fetched['description']!r}"
    )
    assert fetched["ruleRevision"] == current_revision, (
        f"expected revision {current_revision!r} untouched, got {fetched['ruleRevision']!r}"
    )

    # Positive control: updating with the correct, current revision succeeds.
    second_update = client.update_automation_rule(
        ruleArn=rule_arn,
        ruleRevision=current_revision,
        description="second-legit-update",
    )
    assert second_update["description"] == "second-legit-update", (
        f"expected 'second-legit-update', got {second_update['description']!r}"
    )
    assert second_update["ruleRevision"] > current_revision, (
        f"expected revision to advance past {current_revision!r}, got {second_update['ruleRevision']!r}"
    )

    # Terminal read: independent of the mutating call, at the destination.
    final = client.get_automation_rule(ruleArn=rule_arn)
    assert final["description"] == "second-legit-update", (
        f"expected 'second-legit-update' at the destination, got {final['description']!r}"
    )
    assert final["ruleRevision"] == second_update["ruleRevision"], (
        f"expected revision {second_update['ruleRevision']!r} at the destination, "
        f"got {final['ruleRevision']!r}"
    )


def _error_code(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded with {resp!r}")


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
