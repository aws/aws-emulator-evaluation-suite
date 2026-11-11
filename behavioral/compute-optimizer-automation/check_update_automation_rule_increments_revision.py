"""update-automation-rule-increments-revision."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-automation-rule-increments-revision"
GROUP = "lifecycle"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """UpdateAutomationRule persists the new fields and returns a strictly larger ruleRevision."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    name = ctx.unique_name("sim2real-rule-")
    created = client.create_automation_rule(**_rule_kwargs(name, status="Inactive"))
    rule_arn = created["ruleArn"]
    ctx.on_cleanup(lambda: _cleanup_rule(client, rule_arn))
    original_revision = created["ruleRevision"]

    updated = client.update_automation_rule(
        ruleArn=rule_arn,
        ruleRevision=original_revision,
        description="updated-description",
    )
    assert updated["ruleRevision"] > original_revision, (
        f"expected ruleRevision > {original_revision}, got {updated['ruleRevision']}"
    )
    assert updated["description"] == "updated-description", (
        f"expected description 'updated-description', got {updated['description']!r}"
    )

    fetched = client.get_automation_rule(ruleArn=rule_arn)
    assert fetched["description"] == "updated-description", (
        f"expected persisted description 'updated-description', got {fetched['description']!r}"
    )
    assert fetched["ruleRevision"] == updated["ruleRevision"], (
        f"expected independent read to reflect ruleRevision {updated['ruleRevision']}, "
        f"got {fetched['ruleRevision']}"
    )

    # The check already deletes this rule in cleanup; prove the delete is real instead of
    # leaving it unasserted — an independent GetAutomationRule must fail with the specific
    # not-found code once DeleteAutomationRule takes effect, and a mutation that demonstrably
    # worked earlier (UpdateAutomationRule, above) must now fail the same way.
    client.delete_automation_rule(ruleArn=rule_arn, ruleRevision=fetched["ruleRevision"])
    code, message = _client_error(lambda: client.get_automation_rule(ruleArn=rule_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after DeleteAutomationRule, got {code!r}"
    )
    assert message == "The specified resource could not be found", (
        f"unexpected not-found message: {message!r}"
    )

    code, message = _client_error(
        lambda: client.update_automation_rule(
            ruleArn=rule_arn,
            ruleRevision=fetched["ruleRevision"],
            description="post-delete-update",
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from UpdateAutomationRule on a deleted rule, got {code!r}"
    )
    assert message == f"Rule with ARN {rule_arn} does not exist", (
        f"unexpected not-found message from UpdateAutomationRule on a deleted rule: {message!r}"
    )


# ===== helpers (self-contained) =====
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
