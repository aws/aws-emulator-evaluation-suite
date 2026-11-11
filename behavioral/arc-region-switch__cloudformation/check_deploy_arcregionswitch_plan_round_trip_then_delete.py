"""deploy-arcregionswitch-plan-round-trip-then-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-arcregionswitch-plan-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["arc-region-switch", "cloudformation"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


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


# ---- Check-specific: the template, then run(). ----

_NOT_FOUND_CODE = "ResourceNotFoundException"


def _template(name, region_a, region_b):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "arc-region-switch.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                },
            },
            "Plan": {
                "Type": "AWS::ARCRegionSwitch::Plan",
                "Properties": {
                    "Name": name,
                    "ExecutionRole": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                    "RecoveryApproach": "activePassive",
                    "Regions": [region_a, region_b],
                    "PrimaryRegion": region_a,
                    "Workflows": [{"WorkflowTargetAction": "activate"}],
                    "Tags": {"sim2real-plan": name},
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["ExecutionRole", "Arn"]}},
            "PlanRef": {"Value": {"Ref": "Plan"}},
            "PlanArn": {"Value": {"Fn::GetAtt": ["Plan", "Arn"]}},
            "PlanOwner": {"Value": {"Fn::GetAtt": ["Plan", "Owner"]}},
            "PlanVersion": {"Value": {"Fn::GetAtt": ["Plan", "Version"]}},
        },
    })


def _own_plans_by_name(arc, name):
    plans = paginate(arc, "list_plans", "plans")
    return [p for p in plans if p["name"] == name]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ARCRegionSwitch Plan round-trips through arc-region-switch, then deletes.

    Ref is the plan's ARN, every GetAtt and templated property matches an independent ListPlans
    and GetPlan read, and deleting the stack removes the plan from both ListPlans and GetPlan.
    """
    cf = ctx.client("cloudformation")
    arc = ctx.client("arc-region-switch")
    stack = ctx.unique_name("sim2real-cfnarc-rt-")
    name = ctx.unique_name("sim2real-arc-")[:32].rstrip("-")
    region_a = ctx.region
    region_b = "us-west-2" if region_a != "us-west-2" else "us-east-1"

    stack_id = create_stack(ctx, cf, stack, _template(name, region_a, region_b),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    # Ref against an independent read (ListPlans by the declared name), never a read by the Ref.
    matches = _own_plans_by_name(arc, name)
    assert len(matches) == 1, f"ListPlans found {matches!r} for the plan named {name!r}"
    listed = matches[0]
    assert listed["arn"] == out["PlanRef"], (
        f"ListPlans arn {listed['arn']!r} != stack Ref {out['PlanRef']!r}"
    )

    # Read-only GetAtt values == the independently discovered service value.
    assert out["PlanArn"] == listed["arn"], f"GetAtt Arn {out['PlanArn']!r} != {listed['arn']!r}"
    assert out["PlanOwner"] == listed["owner"], (
        f"GetAtt Owner {out['PlanOwner']!r} != ListPlans owner {listed['owner']!r}"
    )
    assert out["PlanOwner"] == ctx.account, f"GetAtt Owner {out['PlanOwner']!r} != {ctx.account!r}"
    assert out["PlanVersion"] == listed["version"], (
        f"GetAtt Version {out['PlanVersion']!r} != ListPlans version {listed['version']!r}"
    )

    # Every templated property, read back by the independently discovered ARN (never the Ref).
    fetched = arc.get_plan(arn=listed["arn"])["plan"]
    assert fetched["name"] == name, f"GetPlan name {fetched['name']!r} != {name!r}"
    assert fetched["executionRole"] == out["RoleArn"], (
        f"GetPlan executionRole {fetched['executionRole']!r} != {out['RoleArn']!r}"
    )
    assert fetched["recoveryApproach"] == "activePassive", (
        f"GetPlan recoveryApproach {fetched['recoveryApproach']!r} != 'activePassive'"
    )
    assert set(fetched["regions"]) == {region_a, region_b}, (
        f"GetPlan regions {fetched['regions']!r} != {{{region_a!r}, {region_b!r}}}"
    )
    assert fetched["primaryRegion"] == region_a, (
        f"GetPlan primaryRegion {fetched['primaryRegion']!r} != {region_a!r}"
    )
    assert len(fetched["workflows"]) == 1, f"GetPlan workflows {fetched['workflows']!r}"
    assert fetched["workflows"][0]["workflowTargetAction"] == "activate", (
        f"GetPlan workflow {fetched['workflows'][0]!r}"
    )

    plan_tags = arc.list_tags_for_resource(arn=listed["arn"]).get("resourceTags", {})
    own_tags = {k: v for k, v in plan_tags.items() if not k.startswith("aws:")}
    assert own_tags == {"sim2real": stack, "sim2real-plan": name}, f"plan tags {own_tags!r}"

    delete_stack(cf, stack_id)

    plan_gone = (_NOT_FOUND_CODE, f"Plan not found for ARN: {listed['arn']}")
    until_raises(lambda: arc.get_plan(arn=listed["arn"]))
    expect_error(lambda: arc.get_plan(arn=listed["arn"]), *plan_gone)
    remaining = _own_plans_by_name(arc, name)
    assert remaining == [], f"the deleted plan is still listed: {remaining!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
