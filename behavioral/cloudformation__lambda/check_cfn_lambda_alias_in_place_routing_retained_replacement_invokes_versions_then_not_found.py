"""cfn-lambda-alias-in-place-routing-retained-replacement-invokes-versions-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-alias-in-place-routing-retained-replacement-invokes-versions-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0
#: Invokes of a 50/50 alias go on this long until both versions ran; routing can lag an update.
_ROUTED_CAP_S = 30.0
_WEIGHT = 0.5

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_HANDLER = (
    "import os\n"
    "\n"
    "\n"
    "def handler(event, context):\n"
    "    return {\n"
    "        'greeting': os.environ['GREETING'],\n"
    "        'version': context.function_version,\n"
    "        'echo': event['probe'],\n"
    "    }\n"
)
#: The greeting each published version was published with.
_GREETING = {"1": "one", "2": "two"}

#: Lambda's refusal of an alias that no longer exists, keyed by the alias ARN.
_NOT_FOUND_CODE = "ResourceNotFoundException"
_NOT_FOUND_MESSAGE = "Cannot find alias arn: {arn}"


def _template(function_name: str, step: int) -> str:
    """The template at *step*: alias live on version 1, then on 2 with half on 1, then prod on 2."""
    resources = {
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
            "Properties": {
                "FunctionName": function_name,
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                "Code": {"ZipFile": _HANDLER},
                "MemorySize": 128,
                "Timeout": 10,
                "Environment": {"Variables": {"GREETING": _GREETING["1" if step == 1 else "2"]}},
                "Tags": _TAGS,
            },
        },
        "VerOne": {"Type": "AWS::Lambda::Version", "Properties": {"FunctionName": {"Ref": "Fn"}}},
    }
    alias = {
        "FunctionName": {"Ref": "Fn"},
        "Name": "live" if step < 3 else "prod",
        "FunctionVersion": {"Fn::GetAtt": ["VerOne" if step == 1 else "VerTwo", "Version"]},
    }
    if step > 1:
        # Published after the function's environment changed, so it captures greeting "two".
        resources["VerTwo"] = {
            "Type": "AWS::Lambda::Version",
            "Properties": {"FunctionName": {"Ref": "Fn"}},
        }
    if step == 2:
        alias["RoutingConfig"] = {
            "AdditionalVersionWeights": [
                {
                    "FunctionVersion": {"Fn::GetAtt": ["VerOne", "Version"]},
                    "FunctionWeight": _WEIGHT,
                }
            ]
        }
    # Name is create-only, so renaming the alias replaces it.
    resources["Alias"] = {
        "Type": "AWS::Lambda::Alias",
        "UpdateReplacePolicy": "Retain",
        "Properties": alias,
    }
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": resources,
            "Outputs": {
                "FnArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}},
                "AliasArn": {"Value": {"Ref": "Alias"}},
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
    """A CloudFormation alias routes invokes as templated, updates in place, survives replacement.

    A version and RoutingConfig change keeps the alias and splits invokes across both versions; a
    Name change under UpdateReplacePolicy Retain keeps the old alias; delete: not found.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-alias.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cfnalias-")
    stack_name = ctx.unique_name("sim2real-cfnalias-stack-")
    ref = {"stack": stack_name}
    retained = {}

    # The replaced alias is retained; it references the stack's versions, so it goes first.
    ctx.on_cleanup(lambda: _teardown_stack(None, cfn, ref))
    ctx.on_cleanup(lambda: _delete_alias(lam, name, retained.get("alias")))

    # ---- 1. create: CloudFormation's view, Lambda's view, and the alias running version 1
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(name, 1),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    fn_arn = _outputs(stack)["FnArn"]
    live_arn = f"{fn_arn}:live"
    assert _outputs(stack)["AliasArn"] == live_arn, f"Ref Alias {_outputs(stack)!r}"
    assert _physical_ids(cfn, ref["stack"])["Alias"] == live_arn, (
        f"the alias's physical id must be its ARN {live_arn!r}"
    )
    _assert_alias(lam, name, "live", live_arn, "1", None)
    assert _invoke(ctx, lam, name, "live") == "1", "alias live must run version 1"

    # ---- 2. in-place: version 2 with half the traffic on version 1, the same alias
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(name, 2),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    assert (ids["VerOne"], ids["VerTwo"], ids["Alias"]) == (
        f"{fn_arn}:1",
        f"{fn_arn}:2",
        live_arn,
    ), f"the versions and the alias after the in-place update: {ids!r}"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Alias"), live_arn, "Alias")
    _assert_alias(lam, name, "live", live_arn, "2", {"1": _WEIGHT})
    ran: set[str] = set()

    def invoke_live() -> set[str]:
        """One more invoke of alias live; every version run so far."""
        ran.add(_invoke(ctx, lam, name, "live"))
        return ran

    _poll(
        ctx,
        invoke_live,
        lambda v: v == {"1", "2"},
        "alias live to run both versions",
        _ROUTED_CAP_S,
    )

    # ---- 3. replacement under UpdateReplacePolicy Retain: alias prod, alias live kept
    # Recorded first, so a failed or unfinished replacement still releases the versions.
    retained["alias"] = "live"
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(name, 3),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    prod_arn = f"{fn_arn}:prod"
    assert _physical_ids(cfn, ref["stack"])["Alias"] == prod_arn, (
        f"the stack must track the replacement {prod_arn!r}"
    )
    assert _outputs(stack)["AliasArn"] == prod_arn, f"Ref Alias after replacement {stack!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Alias"), live_arn, prod_arn, "Alias"
    )
    _assert_alias(lam, name, "prod", prod_arn, "2", None)
    _assert_alias(lam, name, "live", live_arn, "2", {"1": _WEIGHT})
    assert _invoke(ctx, lam, name, "prod") == "2", "alias prod must run version 2"

    # ---- 4. delete: Lambda no longer knows the stack's alias
    # The retained alias is no longer the stack's; removing it lets the stack delete its versions.
    lam.delete_alias(FunctionName=name, Name="live")
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx, lambda: lam.get_alias(FunctionName=name, Name="prod"), _NOT_FOUND_CODE, "alias prod"
    )
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(arn=prod_arn))
    assert got == want, f"GetAlias prod after the stack delete answered {got!r}, expected {want!r}"


def _assert_alias(lam, fn: str, alias: str, arn: str, version: str, weights) -> None:
    """GetAlias reports the template's alias exactly."""
    got = lam.get_alias(FunctionName=fn, Name=alias)
    view = {
        "AliasArn": got.get("AliasArn"),
        "Name": got.get("Name"),
        "FunctionVersion": got.get("FunctionVersion"),
        "Weights": (got.get("RoutingConfig") or {}).get("AdditionalVersionWeights") or None,
    }
    want = {"AliasArn": arn, "Name": alias, "FunctionVersion": version, "Weights": weights}
    assert view == want, f"GetAlias {arn}: {view!r}, expected {want!r}"


def _invoke(ctx, lam, fn: str, alias: str) -> str:
    """Invoke through the alias; the executed version, whose own environment answered."""
    probe = ctx.unique_name("probe-")
    resp = lam.invoke(
        FunctionName=fn, Qualifier=alias, Payload=json.dumps({"probe": probe}).encode()
    )
    body = resp["Payload"].read().decode()
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"Invoke {fn}:{alias} answered {resp['StatusCode']} {resp.get('FunctionError')!r}: {body!r}"
    )
    version = resp.get("ExecutedVersion")
    want = {"greeting": _GREETING.get(version), "version": version, "echo": probe}
    assert json.loads(body) == want, (
        f"Invoke {fn}:{alias} ran version {version!r} and returned {body!r}, expected {want!r}"
    )
    return version


def _delete_alias(lam, fn: str, alias: str | None) -> None:
    if alias is None:
        return
    try:
        lam.delete_alias(FunctionName=fn, Name=alias)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND_CODE:
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


def _poll(ctx, read, ok, what: str, cap_s: float):
    """Re-read until ``ok(value)`` holds, for an eventually consistent read; the last value."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if ok(value):
            return value
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while waiting for {what}")
            raise AssertionError(f"{what} not reached after {timeout:.0f}s; last read {value!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
