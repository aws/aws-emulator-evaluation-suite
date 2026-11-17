"""cfn-ssm-join-if-importvalue-update-rollback-keeps-old-value."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-join-if-importvalue-update-rollback-keeps-old-value"
GROUP = "conditions"
SERVICES = ["cloudformation", "ssm"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _template(param_name: str, export_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "UseImport": {"Type": "String", "AllowedValues": ["true", "false"]},
            },
            "Conditions": {
                "ImportIt": {"Fn::Equals": [{"Ref": "UseImport"}, "true"]},
            },
            "Resources": {
                "ListParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": param_name,
                        "Type": "StringList",
                        "Value": {
                            "Fn::Join": [
                                ",",
                                {
                                    "Fn::If": [
                                        "ImportIt",
                                        ["a", "b", {"Fn::ImportValue": export_name}],
                                        ["a", "b"],
                                    ]
                                },
                            ]
                        },
                    },
                },
            },
            "Outputs": {
                "Imported": {
                    "Value": {"Fn::If": ["ImportIt", {"Fn::ImportValue": export_name}, "safe"]}
                },
            },
        }
    )


def _poll_terminal(cfn, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    """Poll DescribeStacks until the stack's StackStatus is a create/update terminal value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name!r} did not reach a terminal status within {timeout_s}s (last={last!r})"
    )


def _outputs(cfn, stack_name: str) -> dict:
    return {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }


def _stack_events(cfn, stack_name: str) -> list:
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name)
    return [e for page in pages for e in page["StackEvents"]]


def _delete_stack(cfn, stack_name: str) -> None:
    """Delete the stack and raise unless AWS confirms it is gone or already was."""
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") == "ValidationError" and "does not exist" in (err.get("Message") or ""):
            return
        raise
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ValidationError" and "does not exist" in (err.get("Message") or ""):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name!r} delete ended DELETE_FAILED")
        time.sleep(5.0)
    raise AssertionError(f"stack {stack_name!r} did not delete within 300s")


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A false Condition keeps an Fn::If branch holding Fn::ImportValue of a missing export, nested
    in Fn::Join and an Output, unresolved. Flipping it true through UpdateStack rolls the stack
    back naming the missing export, and the parameter keeps its prior value.
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    export_name = ctx.unique_name("sim2real-behav-cfnssm-no-such-export-")
    param_name = ctx.unique_name("sim2real-behav-cfnssm-param-")
    stack_name = ctx.unique_name("sim2real-behav-cfnssm-stack-")
    template = _template(param_name, export_name)

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[{"ParameterKey": "UseImport", "ParameterValue": "false"}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    status = _poll_terminal(cfn, stack_name)
    assert status == "CREATE_COMPLETE", (
        f"a false Condition must leave the missing-export branch unresolved and reach "
        f"CREATE_COMPLETE, got {status!r}"
    )

    value = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert value == "a,b", (
        f"Fn::Join over Fn::If's false branch must store the unjoined list 'a,b', got {value!r}"
    )

    outputs = _outputs(cfn, stack_name)
    assert outputs.get("Imported") == "safe", (
        f"Fn::If's false branch must be the Output value when the Condition is false, "
        f"got {outputs.get('Imported')!r}"
    )

    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[{"ParameterKey": "UseImport", "ParameterValue": "true"}],
    )
    status = _poll_terminal(cfn, stack_name)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"a true Condition must select the branch importing the missing export and roll the "
        f"update back, got {status!r}"
    )

    events = _stack_events(cfn, stack_name)
    expected_reason = f"No export named {export_name} found"
    matching = [
        e for e in events
        if e["LogicalResourceId"] == stack_name
        and e["ResourceStatus"] == "UPDATE_ROLLBACK_IN_PROGRESS"
        and e.get("ResourceStatusReason") == expected_reason
    ]
    assert matching, (
        f"expected a UPDATE_ROLLBACK_IN_PROGRESS stack event reasoned exactly {expected_reason!r}, "
        f"got {[(e['ResourceStatus'], e.get('ResourceStatusReason')) for e in events if e['LogicalResourceId'] == stack_name]!r}"
    )

    value_after = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert value_after == "a,b", (
        f"a rolled-back update must leave the parameter's prior value in place, got {value_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
