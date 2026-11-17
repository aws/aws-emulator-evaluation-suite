"""cfn-activity-name-over-max-length-rejected-with-boundary-control."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-activity-name-over-max-length-rejected-with-boundary-control"
GROUP = "rejected"
SERVICES = ["cloudformation", "stepfunctions"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 300.0


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=180.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def stack_failure_reason(cf, stack_id):
    """The stack's own CREATE_FAILED ``ResourceStatusReason``, oldest match first."""
    kw = {"StackName": stack_id}
    rows = []
    while True:
        page = cf.describe_stack_events(**kw)
        rows.extend(page["StackEvents"])
        token = page.get("NextToken")
        if not token:
            break
        kw["NextToken"] = token
    for e in rows[::-1]:
        if e["PhysicalResourceId"] == stack_id and e["ResourceStatus"] == "CREATE_FAILED":
            return e["ResourceStatusReason"]
    raise AssertionError(f"no stack-level CREATE_FAILED row found for {stack_id}: {rows!r}")


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice."""
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    assert status == "DELETE_COMPLETE", f"stack {stack_id} delete ended {status!r}"


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name>; cleanup registered before the call."""
    created = {}

    def cleanup():
        try:
            stack_id = created.get("StackId")
            if stack_id is None:
                stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
        delete_stack(cf, stack_id)

    ctx.on_cleanup(cleanup)
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def activity_template(name):
    """One AWS::StepFunctions::Activity with no properties besides ``Name``."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "MyActivity": {
                "Type": "AWS::StepFunctions::Activity",
                "Properties": {"Name": name},
            },
        },
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack with an Activity Name one character past the documented 80-char maximum
    rolls back with CloudFormation's own validation failure; a Name at exactly 80 characters
    (the legal boundary) creates successfully and Step Functions describes it under that name.
    """
    cfn, sfn = ctx.client("cloudformation"), ctx.client("stepfunctions")
    prefix = ctx.unique_name("sim2real-behav-sfnactlen-")

    too_long_name = (prefix + "x" * 80)[:81]
    assert len(too_long_name) == 81, f"expected an 81-char name, got {len(too_long_name)}"
    bad_stack = ctx.unique_name("sim2real-behav-sfnactlenbad-")
    bad_stack_id = create_stack(ctx, cfn, bad_stack, activity_template(too_long_name))
    status = wait_stack(cfn, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"
    reason = stack_failure_reason(cfn, bad_stack_id)
    expected_reason = (
        "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list "
        "of issues with resource and property details, resolve each error, then retry "
        "the operation."
    )
    assert reason == expected_reason, f"expected {expected_reason!r}, got {reason!r}"

    ok_name = (prefix + "y" * 80)[:80]
    assert len(ok_name) == 80, f"expected an 80-char name, got {len(ok_name)}"
    ok_stack = ctx.unique_name("sim2real-behav-sfnactlenok-")
    ok_stack_id = create_stack(ctx, cfn, ok_stack, activity_template(ok_name))
    status = wait_stack(cfn, ok_stack_id)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"
    partition = ok_stack_id.split(":")[1]
    arn = f"arn:{partition}:states:{ctx.region}:{ctx.account}:activity:{ok_name}"
    desc = sfn.describe_activity(activityArn=arn)
    assert desc["name"] == ok_name, f"expected name {ok_name!r}, got {desc['name']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
