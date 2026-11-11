"""get-template-summary-returns-accurate-resource-metadata."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-template-summary-returns-accurate-resource-metadata"
GROUP = "data-plane"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTemplateSummary returns ResourceTypes {AWS::SNS::Topic, AWS::IAM::Role}, the parameter with its
    DefaultValue, and Capabilities ["CAPABILITY_IAM"], both for the TemplateBody and for a stack deployed
    from that template (StackName)."""
    cfn = ctx.client("cloudformation")
    parameter_name = "TopicDisplayName"
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            parameter_name: {"Type": "String", "Default": "sim2real-behav"},
        },
        "Resources": {
            "Topic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"DisplayName": {"Ref": parameter_name}},
            },
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "Path": "/sim2real-behav/",
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
        },
    }
    template_body = json.dumps(template)

    static_summary = cfn.get_template_summary(TemplateBody=template_body)
    assert set(static_summary["ResourceTypes"]) == {"AWS::SNS::Topic", "AWS::IAM::Role"}, (
        f"expected ResourceTypes {{AWS::SNS::Topic, AWS::IAM::Role}}, "
        f"got {static_summary['ResourceTypes']!r}"
    )
    static_params = {p["ParameterKey"]: p for p in static_summary["Parameters"]}
    assert parameter_name in static_params, (
        f"expected parameter {parameter_name!r} in static summary, got {sorted(static_params)!r}"
    )
    assert static_params[parameter_name]["DefaultValue"] == "sim2real-behav", (
        f"expected DefaultValue 'sim2real-behav' for {parameter_name!r}, "
        f"got {static_params[parameter_name].get('DefaultValue')!r}"
    )
    assert static_summary["Capabilities"] == ["CAPABILITY_IAM"], (
        f"expected Capabilities ['CAPABILITY_IAM'], got {static_summary['Capabilities']!r}"
    )

    stack_name = ctx.unique_name("sim2real-behav-gts-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    _wait_stack_create_complete(cfn, stack_name)

    live_summary = cfn.get_template_summary(StackName=stack_name)
    assert set(live_summary["ResourceTypes"]) == {"AWS::SNS::Topic", "AWS::IAM::Role"}, (
        f"expected ResourceTypes {{AWS::SNS::Topic, AWS::IAM::Role}} from deployed stack, "
        f"got {live_summary['ResourceTypes']!r}"
    )
    live_params = {p["ParameterKey"]: p for p in live_summary["Parameters"]}
    assert parameter_name in live_params, (
        f"expected parameter {parameter_name!r} in live summary, got {sorted(live_params)!r}"
    )
    assert live_params[parameter_name]["DefaultValue"] == "sim2real-behav", (
        f"expected DefaultValue 'sim2real-behav' for {parameter_name!r} from deployed stack, "
        f"got {live_params[parameter_name].get('DefaultValue')!r}"
    )
    assert live_summary["Capabilities"] == ["CAPABILITY_IAM"], (
        f"expected Capabilities ['CAPABILITY_IAM'] from deployed stack, "
        f"got {live_summary['Capabilities']!r}"
    )


def _wait_stack_create_complete(cfn, stack_name, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if not status.endswith("IN_PROGRESS"):
            assert status == "CREATE_COMPLETE", f"stack {stack_name} ended in {status}: {stacks[0]}"
            return
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
