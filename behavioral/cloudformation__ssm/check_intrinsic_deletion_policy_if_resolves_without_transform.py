"""intrinsic-deletion-policy-if-resolves-without-transform."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "intrinsic-deletion-policy-if-resolves-without-transform"
GROUP = "intrinsic_functions"
SERVICES = ["cloudformation", "ssm"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0


def _template(*, transform: bool, param_name: str) -> str:
    body = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Mode": {"Type": "String", "Default": "keep"}},
        "Conditions": {"Keep": {"Fn::Equals": [{"Ref": "Mode"}, "keep"]}},
        "Resources": {
            "P": {
                "Type": "AWS::SSM::Parameter",
                "DeletionPolicy": {"Fn::If": ["Keep", "Retain", "Delete"]},
                "Properties": {"Name": param_name, "Type": "String", "Value": "v"},
            },
        },
    }
    if transform:
        body["Transform"] = "AWS::LanguageExtensions"
    return json.dumps(body)


def _wait_terminal(cf, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"{stack_id} still {stack['StackStatus']!r} after {_DEADLINE_S}s")
        time.sleep(3.0)


def _delete_stack(cf, stack_id: str) -> None:
    """DeleteStack, then poll by StackId to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        if stack["StackStatus"] == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}")
        time.sleep(3.0)


def _error(fn) -> tuple:
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _get_param(ssm, name):
    """The parameter's value, or None if it does not exist (ParameterNotFound)."""
    try:
        return ssm.get_parameter(Name=name)["Parameter"]["Value"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ParameterNotFound":
            return None
        raise


def _delete_param(ssm, name) -> None:
    """Delete a parameter the stack retained or should have deleted; only not-found is tolerated."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


def _create(ctx, cf, *, prefix: str, transform: bool, mode: str | None, param_name: str) -> str:
    kwargs = {
        "StackName": ctx.unique_name(prefix),
        "TemplateBody": _template(transform=transform, param_name=param_name),
        "Tags": _TAGS,
    }
    if mode is not None:
        kwargs["Parameters"] = [{"ParameterKey": "Mode", "ParameterValue": mode}]
    if transform:
        kwargs["Capabilities"] = ["CAPABILITY_AUTO_EXPAND"]
    stack_id = cf.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    return stack_id


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An Fn::If DeletionPolicy is accepted by CreateStack without the LanguageExtensions
    transform, and the condition it resolves on determines Retain vs Delete at DeleteStack;
    declaring the transform changes neither the acceptance nor the resolved policy.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-attribute-deletionpolicy.html
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    param_keep = "/" + ctx.unique_name("sim2real-behav-delpol-keep-")
    param_gone = "/" + ctx.unique_name("sim2real-behav-delpol-gone-")
    param_ext = "/" + ctx.unique_name("sim2real-behav-delpol-ext-")
    ctx.on_cleanup(lambda: _delete_param(ssm, param_keep))
    ctx.on_cleanup(lambda: _delete_param(ssm, param_gone))
    ctx.on_cleanup(lambda: _delete_param(ssm, param_ext))

    stack_keep = _create(
        ctx, cf, prefix="sim2real-behav-delpol-keep-", transform=False, mode=None, param_name=param_keep,
    )
    stack_gone = _create(
        ctx, cf, prefix="sim2real-behav-delpol-gone-", transform=False, mode="delete", param_name=param_gone,
    )
    stack_ext = _create(
        ctx, cf, prefix="sim2real-behav-delpol-ext-", transform=True, mode=None, param_name=param_ext,
    )

    for stack_id, param_name, label in (
        (stack_keep, param_keep, "keep"),
        (stack_gone, param_gone, "gone"),
        (stack_ext, param_ext, "ext"),
    ):
        settled = _wait_terminal(cf, stack_id)
        assert settled["StackStatus"] == "CREATE_COMPLETE", (
            f"an Fn::If DeletionPolicy must create without the transform ({label}); got "
            f"{settled['StackStatus']!r}: {settled.get('StackStatusReason')!r}"
        )

    assert _get_param(ssm, param_keep) == "v", f"setup did not provision {param_keep}"
    assert _get_param(ssm, param_gone) == "v", f"setup did not provision {param_gone}"
    assert _get_param(ssm, param_ext) == "v", f"setup did not provision {param_ext}"

    _delete_stack(cf, stack_keep)
    kept = _get_param(ssm, param_keep)
    assert kept == "v", (
        f"Mode=keep must resolve Fn::If to Retain and survive DeleteStack with its original value; "
        f"got {kept!r}"
    )

    _delete_stack(cf, stack_gone)
    gone = _error(lambda: ssm.get_parameter(Name=param_gone))
    assert gone == ("ParameterNotFound", ""), (
        f"Mode=delete must resolve Fn::If to Delete and be removed by DeleteStack; got {gone!r}"
    )

    _delete_stack(cf, stack_ext)
    kept_ext = _get_param(ssm, param_ext)
    assert kept_ext == "v", (
        f"declaring AWS::LanguageExtensions must not change the resolved policy; "
        f"Mode=keep under the transform got {kept_ext!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
