"""cfn-activity-tag-update-keeps-arn-and-removed-on-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-activity-tag-update-keeps-arn-and-removed-on-stack-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "stepfunctions"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; two stacks fit an 1800 s cleanup budget


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    rows = []
    kw = {"StackName": stack_id}
    while True:
        page = cf.describe_stack_events(**kw)
        rows.extend(page["StackEvents"])
        token = page.get("NextToken")
        if not token:
            break
        kw["NextToken"] = token
    return rows[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
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
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def resource_template(activity_name, tag_value):
    """One AWS::StepFunctions::Activity with a single Tags entry ``k=<tag_value>``."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "MyActivity": {
                "Type": "AWS::StepFunctions::Activity",
                "Properties": {
                    "Name": activity_name,
                    "Tags": [{"Key": "k", "Value": tag_value}],
                },
            },
        },
    })


# ---- Check-specific: the template, then run(). ----

@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStack changing only an Activity's Tags value completes UPDATE_COMPLETE, keeps the
    Activity's ARN and creation date (no replacement), and Step Functions lists the new tag
    value; DeleteStack then makes DescribeActivity on that ARN fail ActivityDoesNotExist.
    """
    cfn, sfn = ctx.client("cloudformation"), ctx.client("stepfunctions")
    activity_name = ctx.unique_name("sim2real-behav-sfnacttags-")
    stack_name = ctx.unique_name("sim2real-behav-sfnacttagsstack-")

    stack_id = create_stack(ctx, cfn, stack_name, resource_template(activity_name, "first"))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    partition = stack_id.split(":")[1]
    arn = f"arn:{partition}:states:{ctx.region}:{ctx.account}:activity:{activity_name}"

    before = sfn.describe_activity(activityArn=arn)
    assert before["name"] == activity_name, (
        f"expected name {activity_name!r}, got {before['name']!r}"
    )
    before_tags = {t["key"]: t["value"] for t in
                   sfn.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert before_tags.get("k") == "first", f"expected tag k=first, got {before_tags!r}"

    cfn.update_stack(StackName=stack_id, TemplateBody=resource_template(activity_name, "second"))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", (
        f"update ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    after = sfn.describe_activity(activityArn=arn)
    got = (after["activityArn"], after["creationDate"])
    expected = (arn, before["creationDate"])
    assert got == expected, (
        f"expected same ARN and creation date {expected!r} (no replacement), got {got!r}"
    )
    after_tags = {t["key"]: t["value"] for t in
                  sfn.list_tags_for_resource(resourceArn=arn)["tags"]}
    assert after_tags.get("k") == "second", f"expected tag k=second, got {after_tags!r}"

    delete_stack(cfn, stack_id)
    until_raises(lambda: sfn.describe_activity(activityArn=arn), timeout_s=120.0)
    gone = ("ActivityDoesNotExist", f"Activity Does Not Exist: '{arn}'")
    expect_error(lambda: sfn.describe_activity(activityArn=arn), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
