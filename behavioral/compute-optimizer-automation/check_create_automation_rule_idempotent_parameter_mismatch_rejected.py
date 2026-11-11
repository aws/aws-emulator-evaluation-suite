"""create-automation-rule-idempotent-parameter-mismatch-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-automation-rule-idempotent-parameter-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """Reusing a clientToken with a different rule name than the original call is rejected, and no second rule is made."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    token = ctx.unique_name("s2rtok-")
    name_a = ctx.unique_name("sim2real-rule-a-")
    name_b = ctx.unique_name("sim2real-rule-b-")

    created_a = client.create_automation_rule(
        clientToken=token, **_rule_kwargs(name_a, status="Inactive")
    )
    rule_arn_a = created_a["ruleArn"]
    ctx.on_cleanup(lambda: _cleanup_rule(client, rule_arn_a))

    # Break exactly one thing: same clientToken, different name than the original call.
    code, message = _error_code(
        lambda: client.create_automation_rule(
            clientToken=token, **_rule_kwargs(name_b, status="Inactive")
        )
    )
    assert code == "IdempotentParameterMismatchException", (
        f"expected IdempotentParameterMismatchException for a clientToken reused with a "
        f"mismatched name, got {code!r}"
    )
    assert message == "The request tied to this token is different!", f"unexpected mismatch message: {message!r}"

    # Effect absent: no rule named name_b was created.
    listed_b = client.list_automation_rules(filters=[{"name": "Name", "values": [name_b]}])[
        "automationRules"
    ]
    assert listed_b == [], (
        f"expected no rule named {name_b!r} after the mismatched idempotent create was "
        f"rejected, but list_automation_rules returned {listed_b!r}"
    )

    # Positive control: the original rule (name_a) is intact and untouched.
    fetched_a = client.get_automation_rule(ruleArn=rule_arn_a)
    assert fetched_a["name"] == name_a, (
        f"expected original rule {rule_arn_a} to keep its name {name_a!r} after the rejected "
        f"mismatched replay, got {fetched_a['name']!r}"
    )
    assert fetched_a["ruleRevision"] == created_a["ruleRevision"], (
        f"expected original rule {rule_arn_a} to keep revision "
        f"{created_a['ruleRevision']!r} after the rejected mismatched replay, got "
        f"{fetched_a['ruleRevision']!r}"
    )


def _error_code(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(
        f"expected create_automation_rule to be rejected for reusing a clientToken with "
        f"mismatched parameters, but it SUCCEEDED and returned {result!r}"
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
        "tags": [{"key": "sim2real-env", "value": "behavioral"}],
        "criteria": {
            "resourceArn": [
                {
                    "comparison": "StringEquals",
                    "values": ["arn:aws:ec2:us-east-1:111122223333:volume/vol-0000000000000dead"],
                }
            ]
        },
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
