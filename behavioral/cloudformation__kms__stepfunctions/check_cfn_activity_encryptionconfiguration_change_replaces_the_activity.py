"""cfn-activity-encryptionconfiguration-change-replaces-the-activity."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-activity-encryptionconfiguration-change-replaces-the-activity"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms", "stepfunctions"]

_STACK_CAP_S = 600.0
_POLL_S = 2.0


def _poll(probe, predicate, *, timeout_s: float, interval_s: float = _POLL_S, what: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not met within {timeout_s:.0f}s; last={last!r}")
        time.sleep(interval_s)


def _template(activity_name: str, kms_key_id: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "MyActivity": {
                "Type": "AWS::StepFunctions::Activity",
                "Properties": {
                    "Name": activity_name,
                    "EncryptionConfiguration": {
                        "Type": "CUSTOMER_MANAGED_KMS_KEY",
                        "KmsKeyId": kms_key_id,
                    },
                },
            },
        },
        "Outputs": {
            "ActivityArn": {"Value": {"Ref": "MyActivity"}},
        },
    })


def _settle(cfn, stack_id: str, timeout_s: float = _STACK_CAP_S) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    return _poll(
        lambda: cfn.describe_stacks(StackName=stack_id)["Stacks"][0],
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        timeout_s=timeout_s, what=f"stack {stack_id} settling",
    )


def _outputs(cfn, stack_id: str) -> dict[str, str]:
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


_HANDLER_FAILURE_RE = re.compile(
    r'^Resource handler returned message: "(?P<quoted>[^"]*)" '
    r'\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>\w+)\)$'
)


def _parse_handler_failure(reason: str) -> tuple[str, str]:
    """(quoted message, HandlerErrorCode) of a CFN resource-handler failure reason.

    The RequestToken is a fresh id every run and is deliberately not returned.
    """
    match = _HANDLER_FAILURE_RE.match(reason)
    assert match, f"reason did not match the resource-handler failure shape: {reason!r}"
    return match["quoted"], match["code"]


def _activity_events(cfn, stack_id: str, seen: set[str]) -> list[tuple]:
    """(status, reason, physical id) of MyActivity's events not yet in *seen*, oldest first."""
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    rows = [
        (e["EventId"], e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for page in pages for e in page["StackEvents"]
        if e["LogicalResourceId"] == "MyActivity" and e["EventId"] not in seen
    ]
    return list(reversed(rows))


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Changing an AWS::StepFunctions::Activity's createOnly EncryptionConfiguration while its Name
    stays the same fails the replacement, since the new CreateActivity collides with the still-live
    old Activity; the stack rolls back with the original encryption configuration undisturbed.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-stepfunctions-activity.html
    """
    cfn, kms, sfn = ctx.client("cloudformation"), ctx.client("kms"), ctx.client("stepfunctions")

    key_a = kms.create_key(
        Description="sim2real-behav-sfn-act-cmk-a", KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_a["KeyId"], PendingWindowInDays=7))
    key_b = kms.create_key(
        Description="sim2real-behav-sfn-act-cmk-b", KeyUsage="ENCRYPT_DECRYPT", KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_b["KeyId"], PendingWindowInDays=7))

    stack_name = ctx.unique_name("sim2real-behav-sfnactenc-stack-")
    activity_name = ctx.unique_name("sim2real-behav-sfnactenc-")

    stack_id = {"value": None}
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_name, stack_id))

    stack_id["value"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(activity_name, key_a["Arn"]),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    stack = _settle(cfn, stack_id["value"])
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack ended {stack['StackStatus']!r}, expected CREATE_COMPLETE: "
        f"{_activity_events(cfn, stack_id['value'], set())!r}"
    )
    arn = _outputs(cfn, stack_id["value"])["ActivityArn"]
    want_before = {"type": "CUSTOMER_MANAGED_KMS_KEY", "kmsKeyId": key_a["Arn"],
                   "kmsDataKeyReusePeriodSeconds": 300}
    assert sfn.describe_activity(activityArn=arn)["encryptionConfiguration"] == want_before, (
        f"expected encryptionConfiguration {want_before!r} right after create, got "
        f"{sfn.describe_activity(activityArn=arn)['encryptionConfiguration']!r}"
    )

    # ---- update: the same Name, a different createOnly EncryptionConfiguration
    seen = {eid for eid, _, _, _ in _activity_events(cfn, stack_id["value"], set())}
    cfn.update_stack(
        StackName=stack_id["value"],
        TemplateBody=_template(activity_name, key_b["Arn"]),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack = _settle(cfn, stack_id["value"])
    rows = _activity_events(cfn, stack_id["value"], seen)
    assert stack["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"expected the replacement to fail and roll back, got {stack['StackStatus']!r}: {rows!r}"
    )
    reasons = [reason for _, status, reason, _ in rows if status == "UPDATE_FAILED"]
    assert reasons, f"expected an UPDATE_FAILED event for the replacement attempt; events: {rows!r}"
    quoted, handler_code = _parse_handler_failure(reasons[0])
    assert handler_code == "AlreadyExists", (
        f"expected the replacement's HandlerErrorCode to be AlreadyExists, got {handler_code!r} "
        f"in reason {reasons[0]!r}"
    )
    expected_quoted = (
        "An activity with the same name already exists "
        "(Service: null, Status Code: 0, Request ID: null)"
    )
    assert quoted == expected_quoted, (
        f"expected the wrapped resource-handler message {expected_quoted!r}, got {quoted!r}"
    )

    # ---- the original Activity, and its encryption configuration, survive untouched
    assert _outputs(cfn, stack_id["value"])["ActivityArn"] == arn, (
        "the stack must still track the original Activity after the failed replacement"
    )
    after = sfn.describe_activity(activityArn=arn)
    assert after["encryptionConfiguration"] == want_before, (
        f"the failed replacement must leave encryptionConfiguration at {want_before!r}, got "
        f"{after['encryptionConfiguration']!r}"
    )


def _teardown_stack(cfn, stack_name: str, stack_id: dict) -> None:
    """Delete the stack by its id once known, else by name; a stack that never existed is done."""
    name = stack_id["value"] or stack_name
    try:
        current = cfn.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationError":
            raise
        return
    if current["StackStatus"] == "DELETE_COMPLETE":
        return
    if current["StackStatus"].endswith("_IN_PROGRESS"):
        current = _settle(cfn, current["StackId"])
    if current["StackStatus"] != "DELETE_COMPLETE":
        cfn.delete_stack(StackName=current["StackId"])
        current = _settle(cfn, current["StackId"])
    assert current["StackStatus"] == "DELETE_COMPLETE", (
        f"stack {current['StackId']} delete ended {current['StackStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
