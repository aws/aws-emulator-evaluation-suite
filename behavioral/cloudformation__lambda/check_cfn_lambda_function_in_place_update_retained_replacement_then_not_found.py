"""cfn-lambda-function-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-function-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_HANDLER = (
    "import os\n"
    "\n"
    "\n"
    "def handler(event, context):\n"
    "    return {'greeting': os.environ['GREETING'], 'echo': event['probe']}\n"
)

#: Lambda's refusal of a function that no longer exists, keyed by its unqualified ARN.
_NOT_FOUND_CODE = "ResourceNotFoundException"
_NOT_FOUND_MESSAGE = "Function not found: {arn}"


def _template(function_name: str, greeting: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    },
                },
                "Fn": {
                    "Type": "AWS::Lambda::Function",
                    # FunctionName is create-only, so changing it replaces the function.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "FunctionName": function_name,
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                        "Code": {"ZipFile": _HANDLER},
                        "MemorySize": 128,
                        "Timeout": 10,
                        "Environment": {"Variables": {"GREETING": greeting}},
                        "Tags": _TAGS,
                    },
                },
            },
            "Outputs": {
                "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
                "FnArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}},
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
    """A CloudFormation function reads back as templated, updates in place and survives replacement.

    Invoke returns the handler's payload; an Environment change keeps the function, a FunctionName
    change under UpdateReplacePolicy Retain keeps the old one; delete: ResourceNotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-function.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    first = ctx.unique_name("sim2real-cfnfn-a-")
    second = ctx.unique_name("sim2real-cfnfn-b-")
    stack_name = ctx.unique_name("sim2real-cfnfn-stack-")
    ref = {"stack": stack_name}

    # The replaced function is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_function(lam, first))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create: CloudFormation's view, Lambda's view, and the handler running
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first, "hello"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    outputs = _outputs(stack)
    assert _physical_ids(cfn, ref["stack"])["Fn"] == first, (
        f"the function's physical id must be its FunctionName {first!r}"
    )
    fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{first}"
    assert outputs["FnArn"] == fn_arn, f"GetAtt Fn.Arn {outputs['FnArn']!r}, expected {fn_arn!r}"
    _assert_config(lam, first, fn_arn, outputs["RoleArn"], "hello")
    _assert_invoke(ctx, lam, first, "hello")

    # ---- 2. in-place: a new Environment value, the same function
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(first, "bonjour"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Fn"] == first, "an in-place update keeps the function"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Fn"), first, "Fn")
    _assert_config(lam, first, fn_arn, outputs["RoleArn"], "bonjour")
    _assert_invoke(ctx, lam, first, "bonjour")

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new function, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(second, "hola"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Fn"] == second, (
        f"the stack must track the replacement {second!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Fn"), first, second, "Fn"
    )
    second_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{second}"
    assert _outputs(stack)["FnArn"] == second_arn, f"GetAtt Fn.Arn after replacement: {stack!r}"
    _assert_config(lam, second, second_arn, outputs["RoleArn"], "hola")
    _assert_invoke(ctx, lam, second, "hola")
    _assert_config(lam, first, fn_arn, outputs["RoleArn"], "bonjour")
    _assert_invoke(ctx, lam, first, "bonjour")

    # ---- 4. delete: Lambda no longer knows the stack's function
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx, lambda: lam.get_function(FunctionName=second), _NOT_FOUND_CODE, f"function {second}"
    )
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(arn=second_arn))
    assert got == want, f"GetFunction after the stack delete answered {got!r}, expected {want!r}"


def _assert_config(lam, name: str, arn: str, role_arn: str, greeting: str) -> None:
    """GetFunction reports the template's configuration exactly."""
    config = lam.get_function(FunctionName=name)["Configuration"]
    got = {
        k: config.get(k)
        for k in (
            "FunctionName",
            "FunctionArn",
            "Runtime",
            "Handler",
            "Role",
            "MemorySize",
            "Timeout",
            "State",
        )
    }
    want = {
        "FunctionName": name,
        "FunctionArn": arn,
        "Runtime": "python3.12",
        "Handler": "index.handler",
        "Role": role_arn,
        "MemorySize": 128,
        "Timeout": 10,
        "State": "Active",
    }
    assert got == want, f"GetFunction {name}: {got!r}, expected {want!r}"
    env = config.get("Environment", {}).get("Variables")
    assert env == {"GREETING": greeting}, (
        f"{name} environment {env!r}, expected GREETING={greeting!r}"
    )


def _assert_invoke(ctx, lam, name: str, greeting: str) -> None:
    """Invoke runs the deployed handler with the deployed environment."""
    probe = ctx.unique_name("probe-")
    resp = lam.invoke(FunctionName=name, Payload=json.dumps({"probe": probe}).encode())
    body = resp["Payload"].read().decode()
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"Invoke {name} answered {resp['StatusCode']} {resp.get('FunctionError')!r}: {body!r}"
    )
    assert json.loads(body) == {"greeting": greeting, "echo": probe}, (
        f"Invoke {name} returned {body!r}, expected greeting {greeting!r} and echo {probe!r}"
    )


def _delete_function(lam, name: str) -> None:
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND_CODE:
            raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message.
    """
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
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


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
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
