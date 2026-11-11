"""tag-untag-automation-rule-round-trip."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-untag-automation-rule-round-trip"
GROUP = "lifecycle"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """TagResource/UntagResource/ListTagsForResource round-trip on an automation rule."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    name = ctx.unique_name("sim2real-rule-")
    created = client.create_automation_rule(**_rule_kwargs(name, status="Inactive"))
    rule_arn = created["ruleArn"]
    ctx.on_cleanup(lambda: _cleanup_rule(client, rule_arn))

    tags_before = client.list_tags_for_resource(resourceArn=rule_arn)["tags"]
    assert tags_before == [], f"expected no tags on a freshly created rule, got {tags_before!r}"

    client.tag_resource(
        resourceArn=rule_arn,
        ruleRevision=created["ruleRevision"],
        tags=[{"key": "sim2real-env", "value": "behavioral"}],
    )

    tags_after_tag = client.list_tags_for_resource(resourceArn=rule_arn)["tags"]
    assert {"key": "sim2real-env", "value": "behavioral"} in tags_after_tag, (
        f"expected sim2real-env=behavioral in tags after TagResource, got {tags_after_tag!r}"
    )

    current_revision = client.get_automation_rule(ruleArn=rule_arn)["ruleRevision"]
    client.untag_resource(
        resourceArn=rule_arn,
        ruleRevision=current_revision,
        tagKeys=["sim2real-env"],
    )

    tags_after_untag = client.list_tags_for_resource(resourceArn=rule_arn)["tags"]
    assert tags_after_untag == [], (
        f"expected no tags after UntagResource(sim2real-env), got {tags_after_untag!r}"
    )


# ===== helpers (self-contained) =====
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
