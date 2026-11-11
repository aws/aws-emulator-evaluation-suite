"""intrinsic-foreach-expands-resources-and-outputs."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "intrinsic-foreach-expands-resources-and-outputs"
GROUP = "language-extensions"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0
_NAMES = ["Alpha", "Beta"]
_SLUGS = ["blue-1", "red.2"]


def _template() -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Transform": "AWS::LanguageExtensions",
        "Resources": {
            "Fn::ForEach::Handles": ["Name", _NAMES, {
                "Handle${Name}": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            }],
        },
        "Outputs": {
            "Fn::ForEach::ByName": ["Name", _NAMES, {
                "Url${Name}": {"Value": {"Fn::Sub": "${Name}:${AWS::StackName}"}},
            }],
            "Fn::ForEach::BySlug": ["Slug", _SLUGS, {
                "Slug&{Slug}": {"Value": {"Fn::Sub": "${Slug}"}},
            }],
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
    """Fn::ForEach expands one resource and one output per item; ${} keeps the item in the key and
    &{} strips its non-alphanumerics, while the value keeps the item verbatim.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/intrinsic-function-reference-foreach.html
    """
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-foreach-")
    stack_id = cf.create_stack(StackName=name, TemplateBody=_template(),
                               Capabilities=["CAPABILITY_AUTO_EXPAND"], Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _settle(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"got {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )

    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    assert outputs == {
        "UrlAlpha": f"Alpha:{name}",
        "UrlBeta": f"Beta:{name}",
        "Slugblue1": "blue-1",
        "Slugred2": "red.2",
    }, f"the expanded output set differs: {outputs!r}"

    resources = cf.describe_stack_resources(StackName=stack_id)["StackResources"]
    got = sorted((r["LogicalResourceId"], r["ResourceType"], r["ResourceStatus"]) for r in resources)
    assert got == [
        ("HandleAlpha", "AWS::CloudFormation::WaitConditionHandle", "CREATE_COMPLETE"),
        ("HandleBeta", "AWS::CloudFormation::WaitConditionHandle", "CREATE_COMPLETE"),
    ], f"the expanded resource set differs: {got!r}"

    processed = cf.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"]
    assert sorted(processed["Resources"]) == ["HandleAlpha", "HandleBeta"], (
        f"the processed template's Resources: {sorted(processed['Resources'])!r}"
    )
    assert "Transform" not in processed, f"the processed template keeps Transform: {processed!r}"
    original = cf.get_template(StackName=stack_id, TemplateStage="Original")["TemplateBody"]
    assert original == json.loads(_template()), "the Original stage must return the loop as written"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
