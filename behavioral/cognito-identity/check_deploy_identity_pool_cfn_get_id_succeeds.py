"""deploy-identity-pool-cfn-get-id-succeeds."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "deploy-identity-pool-cfn-get-id-succeeds"
GROUP = "deploy"
SERVICES = ["cognito-identity"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  PoolName:
    Type: String
Resources:
  IdentityPool:
    Type: AWS::Cognito::IdentityPool
    Properties:
      IdentityPoolName: !Ref PoolName
      AllowUnauthenticatedIdentities: true
Outputs:
  PoolId:
    Value: !Ref IdentityPool
"""


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Cognito::IdentityPool yields a pool where GetId returns
    a valid IdentityId, and DescribeIdentity — a different operation than the one that minted
    it — confirms that identity actually persisted, proving live behavior beyond CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-cip-")
    pool_name = ctx.unique_name("sim2real-behav-pool-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "PoolName", "ParameterValue": pool_name}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    outputs = _stack_outputs(cfn, stack_name)
    pool_id = outputs["PoolId"]

    cognito = ctx.client("cognito-identity")
    desc = cognito.describe_identity_pool(IdentityPoolId=pool_id)
    assert desc["IdentityPoolId"] == pool_id, (
        f"expected DescribeIdentityPool to reflect {pool_id!r}, got {desc.get('IdentityPoolId')!r}"
    )
    assert desc["IdentityPoolName"] == pool_name, (
        f"expected IdentityPoolName {pool_name!r}, got {desc.get('IdentityPoolName')!r}"
    )
    assert desc["AllowUnauthenticatedIdentities"] is True, (
        f"expected AllowUnauthenticatedIdentities True, got {desc.get('AllowUnauthenticatedIdentities')!r}"
    )

    resp = cognito.get_id(IdentityPoolId=pool_id)
    identity_id = resp["IdentityId"]
    assert re.match(r"^[\w-]+:[0-9a-f-]+$", identity_id), f"malformed IdentityId {identity_id!r}"
    assert identity_id.split(":", 1)[0] == ctx.region, (
        f"expected IdentityId region prefix {ctx.region!r}, got {identity_id!r}"
    )

    # GetId's own response is not proof the identity persisted; DescribeIdentity is an
    # independent operation reading it back at the destination.
    identity_desc = cognito.describe_identity(IdentityId=identity_id)
    assert identity_desc["IdentityId"] == identity_id, (
        f"DescribeIdentity returned {identity_desc.get('IdentityId')!r} for {identity_id!r}"
    )


def _stack_outputs(cfn, stack_name):
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
