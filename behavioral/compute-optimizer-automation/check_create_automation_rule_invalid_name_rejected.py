"""create-automation-rule-invalid-name-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-automation-rule-invalid-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """CreateAutomationRule rejects a name violating the ^[a-zA-Z0-9_-]*$ pattern, and creates nothing."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    bad_name = ctx.unique_name("sim2real-rule-") + " x"  # spaces are not allowed in rule names

    code, message = _client_error(
        lambda: client.create_automation_rule(**_rule_kwargs(bad_name, status="Inactive"))
    )
    assert code == "InvalidParameterValueException", f"unexpected code: {code!r}"
    expected_message = (
        "1 validation error detected: Value at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z0-9_-]*"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no rule with that (invalid) name exists.
    listed = client.list_automation_rules(filters=[{"name": "Name", "values": [bad_name]}])[
        "automationRules"
    ]
    assert listed == []

    # Positive control: a validly-named rule is created successfully.
    good_name = ctx.unique_name("sim2real-rule-")
    good_kwargs = _rule_kwargs(good_name, status="Inactive")
    good_kwargs["tags"] = [{"key": "sim2real-check", "value": CHECK}]
    created = client.create_automation_rule(**good_kwargs)
    rule_arn = created["ruleArn"]
    ctx.on_cleanup(lambda: _cleanup_rule(client, rule_arn))

    # Independent read at the destination, not the mutating call's own echoed response.
    fetched = client.get_automation_rule(ruleArn=rule_arn)
    assert fetched["name"] == good_name


# ===== helpers (self-contained) =====
def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses must not read as a mere code
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
