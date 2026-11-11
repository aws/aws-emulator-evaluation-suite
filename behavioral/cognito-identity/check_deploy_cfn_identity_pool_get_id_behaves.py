"""deploy-cfn-identity-pool-get-id-behaves."""
from __future__ import annotations

import json
import re

from behavioral_harness import tags

CHECK = "deploy-cfn-identity-pool-get-id-behaves"
GROUP = "deploy"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Cognito::IdentityPool accepts GetId calls and
    returns a valid, region-scoped IdentityId; DescribeIdentityPool reflects the
    deployed configuration."""
    cog = ctx.client("cognito-identity")

    pool_name = ctx.unique_name("sim2real-cip-")
    stack_name = ctx.unique_name("sim2real-cfn-cip-")

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "IdentityPool": {
                    "Type": "AWS::Cognito::IdentityPool",
                    "Properties": {
                        "IdentityPoolName": pool_name,
                        "AllowUnauthenticatedIdentities": True,
                    },
                }
            },
            "Outputs": {"IdentityPoolId": {"Value": {"Ref": "IdentityPool"}}},
        }
    )

    outputs = _deploy_stack(ctx, stack_name, template)
    pool_id = outputs["IdentityPoolId"]

    resp = cog.get_id(IdentityPoolId=pool_id)
    identity_id = resp["IdentityId"]
    assert re.match(r"^[\w-]+:[0-9a-f-]+$", identity_id), identity_id
    assert identity_id.startswith(f"{ctx.region}:"), identity_id

    desc = cog.describe_identity_pool(IdentityPoolId=pool_id)
    assert desc["IdentityPoolId"] == pool_id, desc["IdentityPoolId"]
    assert desc["IdentityPoolName"] == pool_name, desc["IdentityPoolName"]
    assert desc["AllowUnauthenticatedIdentities"] is True, desc["AllowUnauthenticatedIdentities"]


def _wait_stack(cfn, stack_name: str, waiter_name: str) -> None:
    waiter = cfn.get_waiter(waiter_name)
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _stack_outputs(cfn, stack_name: str) -> dict:
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    if not stacks:
        raise AssertionError(f"stack {stack_name} not found")
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_stack(cfn, stack_name, "stack_delete_complete")


def _deploy_stack(ctx, stack_name: str, template_body: str, capabilities=None) -> dict:
    cfn = ctx.client("cloudformation")
    kwargs = {"StackName": stack_name, "TemplateBody": template_body}
    if capabilities:
        kwargs["Capabilities"] = capabilities
    cfn.create_stack(Tags=[{"Key": "sim2real:managed", "Value": "true"}], **kwargs)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_stack(cfn, stack_name, "stack_create_complete")
    return _stack_outputs(cfn, stack_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
