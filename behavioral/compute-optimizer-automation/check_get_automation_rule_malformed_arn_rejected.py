"""get-automation-rule-malformed-arn-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-automation-rule-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """GetAutomationRule rejects a ruleArn that does not match the automation-rule ARN pattern at all
    (the malformed ARN fails authorization/resource-pattern matching before reaching resource lookup,
    surfacing as AccessDeniedException rather than InvalidParameterValueException)."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    # Positive control: a real rule can be fetched successfully.
    name = ctx.unique_name("sim2real-rule-")
    created = client.create_automation_rule(**_rule_kwargs(name, status="Inactive"))
    rule_arn = created["ruleArn"]
    ctx.on_cleanup(lambda: _cleanup_rule(client, rule_arn))
    fetched = client.get_automation_rule(ruleArn=rule_arn)
    assert fetched["name"] == name, f"positive control: expected name {name!r}, got {fetched['name']!r}"

    # Break exactly one thing: pass a string that is not an ARN at all.
    code, message = _error_code(lambda: client.get_automation_rule(ruleArn="not-an-arn"))
    assert code == "AccessDeniedException", f"unexpected code: {code!r}"
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    expected_message = (
        f"User: {caller_arn} is not authorized to perform: "
        "aco-automation:GetAutomationRule on resource: not-an-arn"
    )
    assert message == expected_message, f"unexpected malformed-ARN message: {message!r}"


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
