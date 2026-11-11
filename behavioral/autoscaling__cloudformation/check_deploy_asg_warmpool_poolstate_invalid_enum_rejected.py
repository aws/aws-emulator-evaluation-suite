"""deploy-asg-warmpool-poolstate-invalid-enum-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-asg-warmpool-poolstate-invalid-enum-rejected"
GROUP = "deploy"
SERVICES = ["autoscaling", "cloudformation"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


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


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----

_REJECTED = (
    "Invalid request provided: 1 validation error detected: Value 'Terminated' at 'poolState' "
    "failed to satisfy constraint: Member must satisfy enum value set: "
    "[Stopped, Hibernated, Running] (Service: AutoScaling, Status Code: 400, Request ID: <id>) "
    "(SDK Attempt Count: <n>)",
    "InvalidRequest",
)


_AMI_PARAMETER = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


def _template(subnet_id, asg_name, pool_state):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        # The public AMI parameter resolves inside CloudFormation, not through a check call.
        "Parameters": {"ImageId": {"Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                                   "Default": _AMI_PARAMETER}},
        "Resources": {
            "LaunchTemplate": {
                "Type": "AWS::EC2::LaunchTemplate",
                "Properties": {
                    "LaunchTemplateData": {"ImageId": {"Ref": "ImageId"}, "InstanceType": "t3.micro"},
                },
            },
            "ASG": {
                "Type": "AWS::AutoScaling::AutoScalingGroup",
                "Properties": {
                    "AutoScalingGroupName": asg_name,
                    "MinSize": "0",
                    "MaxSize": "1",
                    "DesiredCapacity": "0",
                    "VPCZoneIdentifier": [subnet_id],
                    "LaunchTemplate": {
                        "LaunchTemplateId": {"Ref": "LaunchTemplate"},
                        "Version": {"Fn::GetAtt": ["LaunchTemplate", "LatestVersionNumber"]},
                    },
                },
            },
            "WarmPool": {
                "Type": "AWS::AutoScaling::WarmPool",
                "Properties": {
                    "AutoScalingGroupName": {"Ref": "ASG"},
                    "MinSize": 0,
                    "MaxGroupPreparedCapacity": 0,
                    "PoolState": pool_state,
                },
            },
        },
        "Outputs": {"AsgRef": {"Value": {"Ref": "ASG"}}},
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation WarmPool with an out-of-enum PoolState fails and no warm pool is created.

    The handler refuses "Terminated" and DescribeWarmPool shows none, while the same template with
    "Stopped" deploys a warm pool DescribeWarmPool reads back.
    """
    cf = ctx.client("cloudformation")
    asgc = ctx.client("autoscaling")

    subnet_id = ctx.network().subnet_ids[0]

    # Positive control: the SAME template, the one property given a VALID value (never dropped).
    good_asg = ctx.unique_name("sim2real-cfnwp-good-asg-")
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfnwp-good-"),
                           _template(subnet_id, good_asg, "Stopped"))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[good_asg])["AutoScalingGroups"]
    assert [g["AutoScalingGroupName"] for g in groups] == [stack_outputs(cf, good_id)["AsgRef"]], (
        f"DescribeAutoScalingGroups found {groups!r} for the control"
    )
    good_pool = asgc.describe_warm_pool(AutoScalingGroupName=good_asg)["WarmPoolConfiguration"]
    got = (good_pool.get("PoolState"), good_pool.get("MinSize"),
           good_pool.get("MaxGroupPreparedCapacity"))
    assert got == ("Stopped", 0, 0), f"control warm pool reads {got!r}"

    bad_asg = ctx.unique_name("sim2real-cfnwp-bad-asg-")
    bad_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfnwp-bad-"),
                          _template(subnet_id, bad_asg, "Terminated"))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cf, bad_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    reason = failed_reason(stack_events(cf, bad_id), "WarmPool")
    got = handler_reason(reason, ctx.account, bad_asg)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through AutoScaling, by the name the ASG would have had, before this
    # check's own teardown runs: a CREATE rollback undoes every resource the stack made, so no
    # group -- and therefore no warm pool attached to one -- was left behind.
    groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[bad_asg])["AutoScalingGroups"]
    assert groups == [], f"the rolled-back stack's ASG {bad_asg!r} exists anyway: {groups!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
