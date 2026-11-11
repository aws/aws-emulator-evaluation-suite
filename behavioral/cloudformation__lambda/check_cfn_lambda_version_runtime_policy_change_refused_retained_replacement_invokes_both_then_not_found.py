"""cfn-lambda-version-runtime-policy-change-refused-retained-replacement-invokes-both-then-not-found."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "cfn-lambda-version-runtime-policy-change-refused-retained-replacement-invokes-both-then-"
    "not-found"
)
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0
#: A runtime management read can lag the stack update for a short while.
_CONVERGE_CAP_S = 60.0
#: CloudFormation's refusal of a RuntimePolicy-only change: the version handler publishes again,
#: and Lambda keeps the unchanged function's version 1. The RequestToken differs on every update.
_REFUSED = re.compile(
    re.escape(
        'Resource handler returned message: "A version for this Lambda function exists ( 1 ). '
        'Modify the function to create a new version." (RequestToken: '
    )
    + r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    + re.escape(", HandlerErrorCode: AlreadyExists)")
)

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

#: Lambda's refusal of a version that no longer exists, keyed by the version's qualified ARN.
_NOT_FOUND_CODE = "ResourceNotFoundException"
_NOT_FOUND_MESSAGE = "Function not found: {arn}"


def _template(function_name: str, greeting: str, description: str, update_runtime_on: str) -> str:
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
                "Ver": {
                    "Type": "AWS::Lambda::Version",
                    # Description is create-only, so changing it publishes a new version.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "FunctionName": {"Ref": "Fn"},
                        "Description": description,
                        "RuntimePolicy": {"UpdateRuntimeOn": update_runtime_on},
                    },
                },
            },
            "Outputs": {
                "FnArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}},
                "VerArn": {"Value": {"Ref": "Ver"}},
                "VerNumber": {"Value": {"Fn::GetAtt": ["Ver", "Version"]}},
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
    """A CloudFormation version reads back, refuses a RuntimePolicy change, survives replacement.

    The refused update rolls back and keeps version 1; a Description change under Retain publishes
    version 2 while version 1 still runs its own environment; delete: not found.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-version.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cfnver-")
    stack_name = ctx.unique_name("sim2real-cfnver-stack-")
    ref = {"stack": stack_name}

    # The stack's function owns every version, the retained one included, so the stack is the
    # only teardown.
    ctx.on_cleanup(lambda: _teardown_stack(None, cfn, ref))

    # ---- 1. create: CloudFormation's view, Lambda's view, and version 1 running
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(name, "one", "first", "Auto"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    outputs = _outputs(stack)
    fn_arn = outputs["FnArn"]
    v1_arn = f"{fn_arn}:1"
    assert (outputs["VerArn"], outputs["VerNumber"]) == (v1_arn, "1"), (
        f"Ref Ver and GetAtt Ver.Version {outputs!r}, expected {v1_arn!r} and '1'"
    )
    assert _physical_ids(cfn, ref["stack"])["Ver"] == v1_arn, (
        f"the version's physical id must be its qualified ARN {v1_arn!r}"
    )
    _assert_version(lam, name, "1", v1_arn, "first", "one")
    _assert_runtime_policy(ctx, lam, name, "1", "Auto")
    _assert_invoke(ctx, lam, name, "1", "one")

    # ---- 2. a RuntimePolicy-only change: refused, rolled back, version 1 unchanged
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(name, "one", "first", "FunctionUpdate"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_ROLLBACK_COMPLETE")
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, ref["stack"])
        if e["EventId"] not in seen and e["ResourceStatus"].endswith("_FAILED")
    ]
    assert [(lid, status) for lid, status, _ in failed] == [("Ver", "UPDATE_FAILED")], (
        f"only the version fails its update, got {failed!r}"
    )
    assert _REFUSED.fullmatch(failed[0][2] or ""), (
        f"the version's UPDATE_FAILED reason must be the existing-version refusal: {failed[0][2]!r}"
    )
    assert _physical_ids(cfn, ref["stack"])["Ver"] == v1_arn, "the refusal keeps version 1"
    _assert_version(lam, name, "1", v1_arn, "first", "one")
    _assert_runtime_policy(ctx, lam, name, "1", "Auto")
    _assert_invoke(ctx, lam, name, "1", "one")

    # ---- 3. replacement under UpdateReplacePolicy Retain: version 2, version 1 kept
    # The function's environment changes too, so the publish has new configuration to capture.
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(name, "two", "second", "Auto"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    v2_arn = f"{fn_arn}:2"
    assert _physical_ids(cfn, ref["stack"])["Ver"] == v2_arn, (
        f"the stack must track the replacement {v2_arn!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Ver"), v1_arn, v2_arn, "Ver"
    )
    got = {k: _outputs(stack)[k] for k in ("VerArn", "VerNumber")}
    assert got == {"VerArn": v2_arn, "VerNumber": "2"}, f"version outputs after replacement {got!r}"
    _assert_version(lam, name, "2", v2_arn, "second", "two")
    _assert_version(lam, name, "1", v1_arn, "first", "one")
    listed = [
        v["Version"] for v in lam.list_versions_by_function(FunctionName=name).get("Versions", [])
    ]
    assert listed == ["$LATEST", "1", "2"], f"ListVersionsByFunction {listed!r}"
    _assert_invoke(ctx, lam, name, "2", "two")
    _assert_invoke(ctx, lam, name, "1", "one")

    # ---- 4. delete: Lambda no longer knows the function's versions
    _delete_stack(ctx, cfn, ref["stack"])
    for number, arn in (("2", v2_arn), ("1", v1_arn)):
        got = _wait_error(
            ctx,
            lambda number=number: lam.get_function_configuration(
                FunctionName=name, Qualifier=number
            ),
            _NOT_FOUND_CODE,
            f"version {arn}",
        )
        want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(arn=arn))
        assert got == want, (
            f"GetFunctionConfiguration {arn} after the stack delete answered {got!r}, "
            f"expected {want!r}"
        )


def _assert_version(lam, name: str, number: str, arn: str, description: str, greeting: str):
    """GetFunctionConfiguration of the version reports the template's values exactly."""
    config = lam.get_function_configuration(FunctionName=name, Qualifier=number)
    got = {k: config.get(k) for k in ("FunctionName", "FunctionArn", "Version", "Description")}
    want = {"FunctionName": name, "FunctionArn": arn, "Version": number, "Description": description}
    assert got == want, f"GetFunctionConfiguration {arn}: {got!r}, expected {want!r}"
    env = config.get("Environment", {}).get("Variables")
    assert env == {"GREETING": greeting}, f"{arn} environment {env!r}, expected {greeting!r}"


def _assert_runtime_policy(ctx, lam, name: str, number: str, update_runtime_on: str) -> None:
    """GetRuntimeManagementConfig of the version reports the template's UpdateRuntimeOn."""
    got = _poll(
        ctx,
        lambda: lam.get_runtime_management_config(FunctionName=name, Qualifier=number).get(
            "UpdateRuntimeOn"
        ),
        lambda v: v == update_runtime_on,
        f"runtime management of {name}:{number}",
        _CONVERGE_CAP_S,
    )
    assert got == update_runtime_on, (
        f"runtime management of {name}:{number} is {got!r}, expected {update_runtime_on!r}"
    )


def _assert_invoke(ctx, lam, name: str, number: str, greeting: str) -> None:
    """Invoke of the version runs that version with the environment it was published with."""
    probe = ctx.unique_name("probe-")
    resp = lam.invoke(
        FunctionName=name, Qualifier=number, Payload=json.dumps({"probe": probe}).encode()
    )
    body = resp["Payload"].read().decode()
    assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
        f"Invoke {name}:{number} answered {resp['StatusCode']} {resp.get('FunctionError')!r}: "
        f"{body!r}"
    )
    assert resp.get("ExecutedVersion") == number, (
        f"Invoke {name}:{number} ran version {resp.get('ExecutedVersion')!r}"
    )
    want = {"greeting": greeting, "version": number, "echo": probe}
    assert json.loads(body) == want, f"Invoke {name}:{number} returned {body!r}, expected {want!r}"


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
