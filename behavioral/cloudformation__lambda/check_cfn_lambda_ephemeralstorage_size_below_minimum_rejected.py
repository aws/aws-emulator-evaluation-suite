"""cfn-lambda-ephemeralstorage-size-below-minimum-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-ephemeralstorage-size-below-minimum-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "logs"]

_STACK_CAP_S = 300.0
_POLL_S = 2.0
_BELOW_MIN_MB = 511
_MIN_MB = 512

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_HANDLER = "def handler(event, context):\n    return event\n"

_WANT_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
    "with resource and property details, resolve each error, then retry the operation."
)


def _template(function_name: str, size_mb: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
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
                    "Timeout": 10,
                    "MemorySize": 128,
                    "EphemeralStorage": {"Size": size_mb},
                    "Tags": _TAGS,
                },
            },
        },
    })


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS::Lambda::Function below EphemeralStorage's documented 512 MB floor
    rolls back the stack and creates no function; the identical template at the floor succeeds.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-ephemeralstorage.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    # ---- positive control: the floor value deploys cleanly
    good_name = ctx.unique_name("sim2real-cfnesneg-good-")
    good_stack = ctx.unique_name("sim2real-cfnesneg-goodstk-")
    good_ref = {"stack": good_stack}
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{good_name}"))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, good_ref))
    good_ref["stack"] = cfn.create_stack(
        StackName=good_stack, TemplateBody=_template(good_name, _MIN_MB),
        Capabilities=["CAPABILITY_IAM"], Tags=_TAGS,
    )["StackId"]
    _expect(cfn, _settle(ctx, cfn, good_ref["stack"]), "CREATE_COMPLETE")
    size = lam.get_function_configuration(FunctionName=good_name)["EphemeralStorage"]["Size"]
    assert size == _MIN_MB, f"the floor-sized function reports EphemeralStorage.Size={size!r}, expected {_MIN_MB}"

    # ---- break exactly one thing: one MB below the floor
    bad_name = ctx.unique_name("sim2real-cfnesneg-bad-")
    bad_stack = ctx.unique_name("sim2real-cfnesneg-badstk-")
    bad_ref = {"stack": bad_stack}
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, bad_ref))
    bad_ref["stack"] = cfn.create_stack(
        StackName=bad_stack, TemplateBody=_template(bad_name, _BELOW_MIN_MB),
        Capabilities=["CAPABILITY_IAM"], Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, bad_ref["stack"])
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"a Size below the floor must roll the stack back, got {stack['StackStatus']!r}"
    )
    events = _events(cfn, bad_ref["stack"])
    assert not any(e["LogicalResourceId"] == "Fn" for e in events), (
        f"a Size below the floor must fail CloudFormation's own property validation before Fn is "
        f"ever touched, but it was: {[(e['LogicalResourceId'], e['ResourceStatus']) for e in events]!r}"
    )
    create_failed = [
        e.get("ResourceStatusReason") for e in events if e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert create_failed == [_WANT_REASON], (
        f"the stack's CREATE_FAILED reason was {create_failed!r}, expected [{_WANT_REASON!r}]"
    )

    # ---- the effect is absent: no function was ever created
    got = _error(lambda: lam.get_function(FunctionName=bad_name))
    want = ("ResourceNotFoundException", f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_name}")
    assert got == want, f"a function from a rolled-back stack must not exist, GetFunction answered {got!r}, expected {want!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group *name* until *reads* consecutive reads find it absent.

    A buffered log stream can recreate the group after the delete that was meant to remove it,
    so one delete is not a teardown; raises if it keeps coming back past its own budget.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        present = any(
            g["logGroupName"] == name
            for g in logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        )
        if present:
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(f"{name} still present after {budget_s}s of deletes")
            time.sleep(interval_s)


def _budget_s(ctx, cap_s):
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _settle(ctx, cfn, stack_id: str) -> dict:
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s")
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
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
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _stack_status_or_gone(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in str(exc):
            return "GONE"
        raise


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    status = _stack_status_or_gone(cfn, ref["stack"])
    if status == "GONE":
        return
    if status.endswith("_IN_PROGRESS"):
        _settle(ctx, cfn, ref["stack"])
    _delete_stack(ctx, cfn, ref["stack"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
