"""intrinsic-length-and-to-json-string-resolve-nested-intrinsics."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "intrinsic-length-and-to-json-string-resolve-nested-intrinsics"
GROUP = "language-extensions"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0

_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Transform": "AWS::LanguageExtensions",
    "Parameters": {
        "Hosts": {"Type": "CommaDelimitedList"},
        "Port": {"Type": "Number"},
    },
    "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    "Outputs": {
        "HostCount": {"Value": {"Fn::Length": {"Ref": "Hosts"}}},
        "SplitCount": {"Value": {"Fn::Length": {"Fn::Split": ["-", "a-b-c-d"]}}},
        "Config": {"Value": {"Fn::ToJsonString": {
            "stack": {"Ref": "AWS::StackName"},
            "port": {"Ref": "Port"},
            "hosts": {"Ref": "Hosts"},
            "first": {"Fn::Select": [0, {"Ref": "Hosts"}]},
            "nested": {"url": {"Fn::Sub": "svc-${Port}"}},
        }}},
        "List": {"Value": {"Fn::ToJsonString": [{"Ref": "Port"}, "x", {"Fn::Join": ["+", ["a", "b"]]}]}},
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


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Fn::Length counts a list parameter and a Fn::Split result, and Fn::ToJsonString serialises an
    object and a list with Ref, Sub, Select and Join resolved inside, as compact JSON.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/intrinsic-function-reference-ToJsonString.html
    """
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-tojson-")
    stack_id = cf.create_stack(
        StackName=name, TemplateBody=_TEMPLATE, Capabilities=["CAPABILITY_AUTO_EXPAND"], Tags=_TAGS,
        Parameters=[{"ParameterKey": "Hosts", "ParameterValue": "alpha,beta,gamma,delta,epsilon"},
                    {"ParameterKey": "Port", "ParameterValue": "8080"}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _settle(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"got {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}
    config = (
        '{"stack":"' + name + '","port":"8080","hosts":["alpha","beta","gamma","delta","epsilon"],'
        '"first":"alpha","nested":{"url":"svc-8080"}}'
    )
    expected = {"HostCount": "5", "SplitCount": "4", "Config": config, "List": '["8080","x","a+b"]'}
    assert outputs == expected, f"outputs differ: expected {expected!r}, got {outputs!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
