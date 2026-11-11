"""template-interface-metadata-in-summary."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "template-interface-metadata-in-summary"
GROUP = "template-summary"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0

_METADATA = {
    "AWS::CloudFormation::Interface": {
        "ParameterGroups": [
            {"Label": {"default": "Network"}, "Parameters": ["CidrBlock", "Zone"]},
            {"Label": {"default": "Naming"}, "Parameters": ["Prefix"]},
        ],
        "ParameterLabels": {
            "CidrBlock": {"default": "Which CIDR block?"},
            "Prefix": {"default": "Name prefix"},
        },
    },
    "Owner": {"team": "platform", "tier": 2},
}

# GetTemplateSummary parses Metadata through the same node model as the rest of the
# template, so a non-string scalar leaf (Owner.tier here) comes back as its string form.
_EXPECTED_METADATA = {**_METADATA, "Owner": {**_METADATA["Owner"], "tier": str(_METADATA["Owner"]["tier"])}}

_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Metadata": _METADATA,
    "Parameters": {
        "CidrBlock": {"Type": "String", "Default": "10.0.0.0/16", "Description": "block"},
        "Zone": {"Type": "String", "Default": "a"},
        "Prefix": {"Type": "String", "Default": "app"},
    },
    "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTemplateSummary of a deployed stack returns the template Metadata, the
    AWS::CloudFormation::Interface groups and labels included, as one JSON string.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-cloudformation-interface.html
    """
    cf = ctx.client("cloudformation")

    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-iface-"), TemplateBody=_TEMPLATE,
                               Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _settle(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"got {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    deployed = cf.get_template_summary(StackName=stack_id)
    assert json.loads(deployed["Metadata"]) == _EXPECTED_METADATA, (
        f"Metadata from the stack: {deployed['Metadata']!r}"
    )
    deployed_declared = sorted((p["ParameterKey"], p["DefaultValue"]) for p in deployed["Parameters"])
    assert deployed_declared == [("CidrBlock", "10.0.0.0/16"), ("Prefix", "app"), ("Zone", "a")], (
        f"the deployed summary's parameters: {deployed_declared!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
