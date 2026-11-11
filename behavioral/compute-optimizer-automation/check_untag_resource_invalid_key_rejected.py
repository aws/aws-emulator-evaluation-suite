"""untag-resource-invalid-key-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "untag-resource-invalid-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """UntagResource with a malformed tag key is rejected and the existing tag is left intact."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    name = ctx.unique_name("sim2real-rule-")
    kwargs = _rule_kwargs(name, status="Inactive")
    kwargs["tags"] = [{"key": "team", "value": "sim2real"}]
    created = client.create_automation_rule(**kwargs)
    rule_arn = created["ruleArn"]
    ctx.on_cleanup(lambda: _cleanup_rule(client, rule_arn))

    # Break exactly one thing: tagKeys contains a character outside the allowed tag-key pattern.
    code, message = _client_error(
        lambda: client.untag_resource(
            resourceArn=rule_arn,
            ruleRevision=created["ruleRevision"],
            tagKeys=["not a valid key!"],
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for a malformed tag key, got {code!r}"
    )
    assert message == "Tag validation failed", f"unexpected message: {message!r}"

    # Effect absent: the original tag is still present.
    tags = client.list_tags_for_resource(resourceArn=rule_arn)["tags"]
    assert {"key": "team", "value": "sim2real"} in tags, (
        f"malformed untag_resource must leave the original tag intact, got {tags!r}"
    )

    # Positive control: untagging with a valid, existing key succeeds.
    current_revision = client.get_automation_rule(ruleArn=rule_arn)["ruleRevision"]
    client.untag_resource(resourceArn=rule_arn, ruleRevision=current_revision, tagKeys=["team"])
    tags_after = client.list_tags_for_resource(resourceArn=rule_arn)["tags"]
    assert tags_after == [], f"expected no tags after untagging the valid key, got {tags_after!r}"


# ===== helpers (self-contained) =====
def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, so an
    over-permissive target accepting a call real AWS refuses is never scored as a code
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
