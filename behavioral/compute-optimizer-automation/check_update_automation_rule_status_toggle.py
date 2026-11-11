"""update-automation-rule-status-toggle."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-automation-rule-status-toggle"
GROUP = "state"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """A rule created Active can be flipped to Inactive via UpdateAutomationRule and Get reflects it."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    name = ctx.unique_name("sim2real-rule-")
    # Status Active is safe here because the criteria never matches a real resource
    # (see _rule_kwargs), so this can never actually implement an action.
    created = client.create_automation_rule(**_rule_kwargs(name, status="Active"))
    rule_arn = created["ruleArn"]
    ctx.on_cleanup(lambda: _cleanup_rule(client, rule_arn))
    assert created["status"] == "Active", f"expected created status Active, got {created['status']!r}"

    fetched = client.get_automation_rule(ruleArn=rule_arn)
    assert fetched["status"] == "Active", f"expected fetched status Active, got {fetched['status']!r}"

    updated = client.update_automation_rule(
        ruleArn=rule_arn,
        ruleRevision=fetched["ruleRevision"],
        status="Inactive",
    )
    assert updated["status"] == "Inactive", f"expected updated status Inactive, got {updated['status']!r}"

    fetched_after = client.get_automation_rule(ruleArn=rule_arn)
    assert fetched_after["status"] == "Inactive", (
        f"expected post-update fetched status Inactive, got {fetched_after['status']!r}"
    )

    # The check already deletes this rule in cleanup; prove the delete is real instead of
    # leaving it unasserted — an independent GetAutomationRule must fail with the
    # specific not-found code once DeleteAutomationRule takes effect.
    client.delete_automation_rule(ruleArn=rule_arn, ruleRevision=fetched_after["ruleRevision"])
    code, message = _client_error(lambda: client.get_automation_rule(ruleArn=rule_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after DeleteAutomationRule, got {code!r}"
    )
    assert message == "The specified resource could not be found", (
        f"unexpected not-found message: {message!r}"
    )


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses must not be masked as a code
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
