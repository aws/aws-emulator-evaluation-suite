"""template-mappings-conditions-output-set."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "template-mappings-conditions-output-set"
GROUP = "conditions"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_DEADLINE_S = 240.0

_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {"Env": {"Type": "String", "AllowedValues": ["prod", "dev"]}},
    "Mappings": {
        "Sizing": {
            "prod": {"Tier": "large", "Replicas": "3"},
            "dev": {"Tier": "small", "Replicas": "1"},
        },
    },
    "Conditions": {
        "IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]},
        "IsDev": {"Fn::Not": [{"Condition": "IsProd"}]},
    },
    "Resources": {
        "Always": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        "ProdOnly": {"Type": "AWS::CloudFormation::WaitConditionHandle", "Condition": "IsProd"},
    },
    "Outputs": {
        "Tier": {"Value": {"Fn::FindInMap": ["Sizing", {"Ref": "Env"}, "Tier"]}},
        "Summary": {"Value": {"Fn::Join": [":", [
            {"Ref": "Env"},
            {"Fn::FindInMap": ["Sizing", {"Ref": "Env"}, "Replicas"]},
            {"Fn::If": ["IsProd", "ha", "single"]},
        ]]}},
        "ProdHandle": {"Condition": "IsProd", "Value": {"Ref": "ProdOnly"}},
        "DevNote": {"Condition": "IsDev", "Value": {"Fn::Sub": "dev-${AWS::StackName}"}},
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
    """Mappings, Conditions and conditional Outputs together: each stack's output set is exactly the
    outputs whose condition holds, with FindInMap and Fn::If values resolved for its parameter.
    """
    cf = ctx.client("cloudformation")
    stacks = {}
    for env in ("prod", "dev"):
        name = ctx.unique_name(f"sim2real-behav-mapcond-{env}-")
        stack_id = cf.create_stack(StackName=name, TemplateBody=_TEMPLATE, Tags=_TAGS,
                                   Parameters=[{"ParameterKey": "Env", "ParameterValue": env}])["StackId"]
        ctx.on_cleanup(lambda s=stack_id: _delete_stack(cf, s))
        stacks[env] = (name, stack_id)

    results = {}
    for env, (name, stack_id) in stacks.items():
        stack = _settle(cf, stack_id)
        assert stack["StackStatus"] == "CREATE_COMPLETE", (
            f"{env}: {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
        )
        results[env] = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

    prod_id = stacks["prod"][1]
    handle = cf.describe_stack_resource(StackName=prod_id, LogicalResourceId="ProdOnly")
    handle_url = handle["StackResourceDetail"]["PhysicalResourceId"]
    assert results["prod"] == {"Tier": "large", "Summary": "prod:3:ha", "ProdHandle": handle_url}, (
        f"prod output set differs: {results['prod']!r}"
    )
    dev_name, dev_id = stacks["dev"]
    assert results["dev"] == {"Tier": "small", "Summary": "dev:1:single", "DevNote": f"dev-{dev_name}"}, (
        f"dev output set differs: {results['dev']!r}"
    )

    dev_resources = sorted(r["LogicalResourceId"] for r in cf.describe_stack_resources(StackName=dev_id)["StackResources"])
    assert dev_resources == ["Always"], f"a false Condition must create no resource; dev has {dev_resources!r}"
    prod_resources = sorted(r["LogicalResourceId"] for r in cf.describe_stack_resources(StackName=prod_id)["StackResources"])
    assert prod_resources == ["Always", "ProdOnly"], f"prod resources: {prod_resources!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
