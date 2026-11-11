"""cfn-nested-stack-in-place-parameter-update-reaches-child-resource-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-nested-stack-in-place-parameter-update-reaches-child-resource-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3", "ssm"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_KEY = "child.json"

#: GetParameter on a missing name answers ParameterNotFound with no message.
_PARAM_NOT_FOUND = ("ParameterNotFound", "")
#: DescribeStacks by name of a stack that no longer exists.
_STACK_NOT_FOUND = ("ValidationError", "Stack with id {name} does not exist")

#: The child: one SSM parameter whose name and value are the parent's parameters.
_CHILD = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"ParamName": {"Type": "String"}, "Greeting": {"Type": "String"}},
        "Resources": {
            "Param": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": {"Ref": "ParamName"},
                    "Type": "String",
                    "Value": {"Ref": "Greeting"},
                },
            }
        },
        "Outputs": {"ParamName": {"Value": {"Ref": "Param"}}},
    }
)


def _template(template_url: str, param_name: str, greeting: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                # AWS::CloudFormation::Stack has no create-only property, so no update replaces it.
                "Child": {
                    "Type": "AWS::CloudFormation::Stack",
                    "Properties": {
                        "TemplateURL": template_url,
                        "Parameters": {"ParamName": param_name, "Greeting": greeting},
                        "Tags": _TAGS,
                    },
                }
            },
            "Outputs": {
                "ChildId": {"Value": {"Ref": "Child"}},
                "ChildParam": {"Value": {"Fn::GetAtt": ["Child", "Outputs.ParamName"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A nested stack from an S3 TemplateURL builds its child stack and the child's parameter.

    A parent Parameters change updates the child and its parameter in place (no property forces
    a replacement); deleting the parent deletes both: DELETE_COMPLETE and ParameterNotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cloudformation-stack.html
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    ssm = ctx.client("ssm")
    bucket = ctx.unique_name("sim2real-cfnnest-")
    param_name = "/" + ctx.unique_name("sim2real-cfnnest-param-")
    stack_name = ctx.unique_name("sim2real-cfnnest-stack-")
    ref = {"stack": stack_name}

    # The template bucket outlives the stack's reads of it, so it is torn down last.
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    ctx.on_cleanup(lambda: _teardown_stack(None, cfn, ref))
    create = {"Bucket": bucket}
    # CreateBucket in us-east-1 takes no LocationConstraint.
    if ctx.region != "us-east-1":
        create["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create)
    s3.put_object(Bucket=bucket, Key=_KEY, Body=_CHILD.encode())
    # CloudFormation reads the child template from the object's own regional S3 URL.
    template_url = f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{_KEY}"

    # ---- 1. create: the parent's view, the child stack's own view, and SSM's view
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(template_url, param_name, "hello"),
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    # An output whose value did not resolve is a mismatch, not a missing key.
    out = {o["OutputKey"]: o.get("OutputValue") for o in stack.get("Outputs", [])}
    child_id = _physical_ids(cfn, ref["stack"])["Child"]
    child_name = child_id.split("/")[1]
    assert out == {"ChildId": child_id, "ChildParam": param_name}, (
        f"parent outputs {out!r}, expected Ref Child {child_id!r} and the child's ParamName"
    )
    assert child_name.startswith(f"{stack_name}-Child-"), (
        f"the child stack's name {child_name!r} must be the parent's name and the logical id"
    )
    _assert_child(cfn, child_id, ref["stack"], "CREATE_COMPLETE", param_name, "hello")
    assert _physical_ids(cfn, child_id) == {"Param": param_name}, "the child holds the parameter"
    _assert_parameter(ssm, param_name, "hello", 1)

    # ---- 2. in-place: a new Greeting passed down, the same child stack and parameter
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    seen_child = {e["EventId"] for e in _events(cfn, child_id)}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(template_url, param_name, "bonjour"),
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Child"] == child_id, "an update keeps the child stack"
    # A nested stack resource reports UPDATE_COMPLETE twice: once when the child stack's update
    # completes, once more when the parent's update completes its cleanup.
    rows = _rows(_events(cfn, ref["stack"]), seen, "Child")
    want = [
        (s, None, child_id) for s in ("UPDATE_IN_PROGRESS", "UPDATE_COMPLETE", "UPDATE_COMPLETE")
    ]
    assert rows == want, (
        f"Child must update in place as the same child stack, its events were {rows!r}"
    )
    _assert_child(cfn, child_id, ref["stack"], "UPDATE_COMPLETE", param_name, "bonjour")
    _assert_in_place(_rows(_events(cfn, child_id), seen_child, "Param"), param_name, "Param")
    _assert_parameter(ssm, param_name, "bonjour", 2)

    # ---- 3. delete: the parent's delete deletes the child stack and its parameter
    _delete_stack(ctx, cfn, ref["stack"])
    child = cfn.describe_stacks(StackName=child_id)["Stacks"][0]
    assert child["StackStatus"] == "DELETE_COMPLETE", (
        f"the child stack must be deleted with its parent: {child['StackStatus']!r}"
    )
    got = _error(lambda: cfn.describe_stacks(StackName=child_name))
    want = (_STACK_NOT_FOUND[0], _STACK_NOT_FOUND[1].format(name=child_name))
    assert got == want, f"DescribeStacks {child_name} after the delete answered {got!r}"
    got = _wait_error(
        ctx,
        lambda: ssm.get_parameter(Name=param_name),
        _PARAM_NOT_FOUND[0],
        f"parameter {param_name}",
    )
    assert got == _PARAM_NOT_FOUND, f"GetParameter after the stack delete answered {got!r}"


def _assert_child(cfn, child_id: str, parent_id: str, status: str, name: str, greeting: str):
    """DescribeStacks of the child names the parent and carries the parent's parameters."""
    child = cfn.describe_stacks(StackName=child_id)["Stacks"][0]
    got = {
        "StackStatus": child.get("StackStatus"),
        "ParentId": child.get("ParentId"),
        "RootId": child.get("RootId"),
        "Parameters": {p["ParameterKey"]: p["ParameterValue"] for p in child.get("Parameters", [])},
        "Outputs": _outputs(child),
    }
    want = {
        "StackStatus": status,
        "ParentId": parent_id,
        "RootId": parent_id,
        "Parameters": {"ParamName": name, "Greeting": greeting},
        "Outputs": {"ParamName": name},
    }
    assert got == want, f"DescribeStacks {child_id}: {got!r}, expected {want!r}"


def _assert_parameter(ssm, name: str, value: str, version: int) -> None:
    """GetParameter returns the value the parent passed down, at the expected version."""
    p = ssm.get_parameter(Name=name)["Parameter"]
    got = (p["Name"], p["Type"], p["Value"], p["Version"])
    assert got == (name, "String", value, version), (
        f"GetParameter {name}: {got!r}, expected {(name, 'String', value, version)!r}"
    )


def _delete_bucket(s3, bucket: str) -> None:
    """Delete the template object and the bucket; a bucket that never existed is done."""
    try:
        s3.delete_object(Bucket=bucket, Key=_KEY)
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. A teardown passes ``ctx=None`` and waits the full
    cap_s; in a teardown, ctx.time_left() counts down the runner's cleanup timeout.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done."""
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"])
    _delete_stack(ctx, cfn, stack["StackId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
