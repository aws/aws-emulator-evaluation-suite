"""parameter-ssm-list-resolved-value-until-update."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-ssm-list-resolved-value-until-update"
GROUP = "stack_parameters"
SERVICES = ["cloudformation", "ssm"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0


def _template(revision: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Zones": {"Type": "AWS::SSM::Parameter::Value<List<String>>"},
            "Extra": {"Type": "CommaDelimitedList", "Default": "x, y ,z"},
        },
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle",
                                 "Metadata": {"Revision": revision}}},
        "Outputs": {
            "Second": {"Value": {"Fn::Select": [1, {"Ref": "Zones"}]}},
            "Joined": {"Value": {"Fn::Join": ["|", {"Ref": "Zones"}]}},
            "ExtraLast": {"Value": {"Fn::Select": [2, {"Ref": "Extra"}]}},
        },
    })


def _settle(cf, stack_id: str, start: str = "") -> dict:
    """Poll DescribeStacks by StackId until the status is neither *_IN_PROGRESS nor ``start``."""
    deadline = time.monotonic() + _DEADLINE_S
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        if not status.endswith("_IN_PROGRESS") and status != start:
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


def _view(stack: dict) -> tuple[dict, dict]:
    params = {p["ParameterKey"]: (p["ParameterValue"], p.get("ResolvedValue")) for p in stack["Parameters"]}
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return params, outputs


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Value<List<String>> parameter resolves a StringList to a comma-joined ResolvedValue that
    Fn::Select indexes; a later SSM change shows only after a stack update re-resolves it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-supplied-parameter-types.html
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    name = "/" + ctx.unique_name("sim2real-behav-ssmlist-")
    ssm.put_parameter(Name=name, Type="StringList", Value="alpha,beta,gamma", Tags=_TAGS)
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=name), "ParameterNotFound"))

    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-ssmlist-"), TemplateBody=_template("1"),
                               Parameters=[{"ParameterKey": "Zones", "ParameterValue": name}], Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _settle(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"got {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    params, outputs = _view(stack)
    assert params == {"Zones": (name, "alpha,beta,gamma"), "Extra": ("x,y,z", None)}, f"Parameters: {params!r}"
    assert outputs == {"Second": "beta", "Joined": "alpha|beta|gamma", "ExtraLast": "z"}, f"Outputs: {outputs!r}"

    ssm.put_parameter(Name=name, Type="StringList", Value="delta,epsilon", Overwrite=True)
    params, outputs = _view(cf.describe_stacks(StackName=stack_id)["Stacks"][0])
    assert params["Zones"] == (name, "alpha,beta,gamma"), f"a deployed stack must keep its resolution; {params!r}"
    assert outputs["Second"] == "beta", f"outputs must not follow SSM without an update; {outputs!r}"

    cf.update_stack(StackName=stack_id, TemplateBody=_template("2"),
                    Parameters=[{"ParameterKey": "Zones", "UsePreviousValue": True},
                                {"ParameterKey": "Extra", "UsePreviousValue": True}])
    updated = _settle(cf, stack_id, start="CREATE_COMPLETE")
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"got {updated['StackStatus']!r}: {updated.get('StackStatusReason')!r}"
    )
    params, outputs = _view(updated)
    assert params == {"Zones": (name, "delta,epsilon"), "Extra": ("x,y,z", None)}, f"after update: {params!r}"
    assert outputs == {"Second": "epsilon", "Joined": "delta|epsilon", "ExtraLast": "z"}, f"after update: {outputs!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
