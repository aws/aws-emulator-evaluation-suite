"""intrinsic-deletion-policy-if-honoured-on-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "intrinsic-deletion-policy-if-honoured-on-delete"
GROUP = "language-extensions"
SERVICES = ["cloudformation", "ssm"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0


def _template(kept: str, dropped: str) -> str:
    def param(name: str, policy: dict) -> dict:
        return {
            "Type": "AWS::SSM::Parameter",
            "DeletionPolicy": policy,
            "Properties": {"Name": name, "Type": "String", "Value": "sim2real"},
        }

    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Transform": "AWS::LanguageExtensions",
        "Parameters": {"Mode": {"Type": "String", "AllowedValues": ["keep", "drop"]}},
        "Conditions": {"Keep": {"Fn::Equals": [{"Ref": "Mode"}, "keep"]}},
        "Resources": {
            "Kept": param(kept, {"Fn::If": ["Keep", "Retain", "Delete"]}),
            "Dropped": param(dropped, {"Fn::If": ["Keep", "Delete", "Retain"]}),
        },
    })


def _settle(cf, stack_id: str) -> dict:
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
    # The first read after DeleteStack may still show the prior status, so only the two terminal
    # delete states end the poll.
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] == "DELETE_COMPLETE":
            return
        if stack["StackStatus"] == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack_id} ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
            )
        time.sleep(3.0)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, except the named not-found codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> tuple:
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Under AWS::LanguageExtensions a DeletionPolicy written as Fn::If resolves per stack: on
    DeleteStack the parameter resolved to Retain survives and the one resolved to Delete is gone.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/transform-aws-languageextensions.html
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    kept = "/" + ctx.unique_name("sim2real-behav-delpol-kept-")
    dropped = "/" + ctx.unique_name("sim2real-behav-delpol-dropped-")
    for name in (kept, dropped):
        ctx.on_cleanup(_teardown(lambda n=name: ssm.delete_parameter(Name=n), "ParameterNotFound"))

    stack_id = cf.create_stack(
        StackName=ctx.unique_name("sim2real-behav-delpol-"), TemplateBody=_template(kept, dropped),
        Parameters=[{"ParameterKey": "Mode", "ParameterValue": "keep"}],
        Capabilities=["CAPABILITY_AUTO_EXPAND"], Tags=_TAGS,
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _settle(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"got {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    processed = cf.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"]
    policies = {k: v.get("DeletionPolicy") for k, v in processed["Resources"].items()}
    assert policies == {"Kept": "Retain", "Dropped": "Delete"}, (
        f"the processed template must carry the resolved policies; got {policies!r}"
    )

    _delete_stack(cf, stack_id)
    latest: dict = {}
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for e in page["StackEvents"]:
            latest.setdefault(e["LogicalResourceId"], e["ResourceStatus"])
    finals = {k: latest.get(k) for k in ("Kept", "Dropped")}
    assert finals == {"Kept": "DELETE_SKIPPED", "Dropped": "DELETE_COMPLETE"}, (
        f"the last event of each parameter differs: {finals!r}"
    )

    value = ssm.get_parameter(Name=kept)["Parameter"]["Value"]
    assert value == "sim2real", f"the retained parameter must survive with its value; got {value!r}"
    code = _error(lambda: ssm.get_parameter(Name=dropped))
    assert code == ("ParameterNotFound", ""), f"the parameter resolved to Delete must be gone; got {code!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
