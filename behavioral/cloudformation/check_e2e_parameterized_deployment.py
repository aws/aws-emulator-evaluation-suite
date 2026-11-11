"""e2e-parameterized-deployment."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-parameterized-deployment"
GROUP = 'e2e_workflows'
SERVICES = ['cloudformation']


_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}

def _wait_terminal(cf, name, timeout_s=180):
    """Poll DescribeStacks until the stack reaches a terminal state; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")

def _create_and_wait(ctx, cf, template, *, parameters=None, tags=None, capabilities=None):
    """CreateStack (registered for teardown) and wait for CREATE_COMPLETE; return the name."""
    name = ctx.unique_name("sim2real-behav-stk-")
    kwargs = {"StackName": name, "TemplateBody": template}
    if parameters:
        kwargs["Parameters"] = parameters
    if tags:
        kwargs["Tags"] = tags
    if capabilities:
        kwargs["Capabilities"] = capabilities
    cf.create_stack(**kwargs)
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    status = _wait_terminal(cf, name)
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {status}, expected CREATE_COMPLETE")
    return name


def _template():
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "Env": {
                    "Type": "String",
                    "AllowedValues": ["dev", "prod"],
                    "Default": "dev",
                },
                "FeatureFlag": {
                    "Type": "String",
                    "AllowedValues": ["true", "false"],
                    "Default": "false",
                },
            },
            "Conditions": {
                "FeatureEnabled": {"Fn::Equals": [{"Ref": "FeatureFlag"}, "true"]},
            },
            "Resources": {
                "BaseHandle": {
                    "Type": "AWS::CloudFormation::WaitConditionHandle",
                },
                "FeatureHandle": {
                    "Type": "AWS::CloudFormation::WaitConditionHandle",
                    "Condition": "FeatureEnabled",
                },
            },
            "Outputs": {
                "Environment": {
                    "Value": {"Ref": "Env"},
                },
                "FeatureActive": {
                    "Value": {"Fn::If": ["FeatureEnabled", "yes", "no"]},
                },
            },
        }
    )


def _deploy_and_read(ctx, cf, *, env, feature_flag):
    name = _create_and_wait(
        ctx, cf, _template(),
        parameters=[
            {"ParameterKey": "Env", "ParameterValue": env},
            {"ParameterKey": "FeatureFlag", "ParameterValue": feature_flag},
        ],
    )
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cf.describe_stacks(StackName=name)["Stacks"][0].get("Outputs", [])
    }
    resp = cf.list_stack_resources(StackName=name)
    logical_ids = {r["LogicalResourceId"] for r in resp["StackResourceSummaries"]}
    return outputs, logical_ids


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Conditions gate a resource on parameters: with FeatureFlag=false the stack outputs
    Environment=dev and FeatureActive=no and omits FeatureHandle; with FeatureFlag=true it
    outputs prod/yes and creates FeatureHandle; BaseHandle exists in both."""
    cf = ctx.client("cloudformation")

    outputs, logical_ids = _deploy_and_read(ctx, cf, env="dev", feature_flag="false")
    assert outputs["Environment"] == "dev", (
        f"Expected Environment=dev, got {outputs.get('Environment')!r}"
    )
    assert outputs["FeatureActive"] == "no", (
        f"Expected FeatureActive=no, got {outputs.get('FeatureActive')!r}"
    )
    assert "BaseHandle" in logical_ids, "BaseHandle should always be created"
    assert "FeatureHandle" not in logical_ids, (
        "FeatureHandle should NOT be created when FeatureFlag=false"
    )

    outputs, logical_ids = _deploy_and_read(ctx, cf, env="prod", feature_flag="true")
    assert outputs["Environment"] == "prod", (
        f"Expected Environment=prod, got {outputs.get('Environment')!r}"
    )
    assert outputs["FeatureActive"] == "yes", (
        f"Expected FeatureActive=yes, got {outputs.get('FeatureActive')!r}"
    )
    assert "BaseHandle" in logical_ids, "BaseHandle should always be created"
    assert "FeatureHandle" in logical_ids, (
        "FeatureHandle SHOULD be created when FeatureFlag=true"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
