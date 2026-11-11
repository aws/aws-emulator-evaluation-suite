"""delete-automation-rule-stale-revision-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-automation-rule-stale-revision-rejected"
GROUP = "overly-permissive"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """DeleteAutomationRule with a stale ruleRevision (optimistic-lock conflict) is rejected with
    InvalidParameterValueException, and the rule survives."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    name = ctx.unique_name("sim2real-rule-")
    created = client.create_automation_rule(**_rule_kwargs(name, status="Inactive"))
    rule_arn = created["ruleArn"]
    ctx.on_cleanup(lambda: _cleanup_rule(client, rule_arn))
    stale_revision = created["ruleRevision"]

    # Bump the revision so stale_revision no longer matches the stored one.
    bumped = client.update_automation_rule(
        ruleArn=rule_arn,
        ruleRevision=stale_revision,
        description="bumped-before-delete-attempt",
    )
    current_revision = bumped["ruleRevision"]
    assert current_revision > stale_revision, (
        f"expected update to increment revision past {stale_revision!r}, got {current_revision!r}"
    )

    # Break exactly one thing: try to delete using the now-stale revision.
    code, message = _client_error(
        lambda: client.delete_automation_rule(ruleArn=rule_arn, ruleRevision=stale_revision)
    )
    assert code == "InvalidParameterValueException", f"unexpected code: {code!r}"
    expected_message = f"Rule revision does not match the current revision number {current_revision}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rule must still exist, untouched by the failed delete.
    still_there = client.get_automation_rule(ruleArn=rule_arn)
    assert still_there["ruleRevision"] == current_revision, (
        f"expected revision to stay at {current_revision!r}, got {still_there['ruleRevision']!r}"
    )
    assert still_there["description"] == "bumped-before-delete-attempt", (
        f"expected description untouched by the rejected delete, got {still_there['description']!r}"
    )

    # Positive control: deleting with the correct, current revision succeeds.
    client.delete_automation_rule(ruleArn=rule_arn, ruleRevision=current_revision)
    final_code, final_message = _client_error(lambda: client.get_automation_rule(ruleArn=rule_arn))
    assert final_code == "ResourceNotFoundException", f"unexpected code: {final_code!r}"
    assert final_message == "The specified resource could not be found", (
        f"unexpected not-found message: {final_message!r}"
    )

    # Deletes prove gone AND unusable: a mutation on the now-dead id also fails not-found.
    mutate_code, mutate_message = _client_error(
        lambda: client.update_automation_rule(
            ruleArn=rule_arn, ruleRevision=current_revision, description="should-never-apply"
        )
    )
    assert mutate_code == "ResourceNotFoundException", f"unexpected code: {mutate_code!r}"
    expected_mutate_message = f"Rule with ARN {rule_arn} does not exist"
    assert mutate_message == expected_mutate_message, (
        f"expected message {expected_mutate_message!r}, got {mutate_message!r}"
    )


# ===== self-contained helpers =====
def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses must not be scored as a code
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
        "criteria": {
            "resourceArn": [
                {
                    "comparison": "StringEquals",
                    "values": ["arn:aws:ec2:us-east-1:111122223333:volume/vol-0000000000000dead"],
                }
            ]
        },
        "tags": [{"key": "sim2real-check", "value": CHECK}],
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
