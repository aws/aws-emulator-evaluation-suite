"""deploy-identity-pool-cfn-role-mappings-enforced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-identity-pool-cfn-role-mappings-enforced"
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
  UnauthRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Federated: cognito-identity.amazonaws.com
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringEquals:
                "cognito-identity.amazonaws.com:aud": !Ref IdentityPool
              "ForAnyValue:StringLike":
                "cognito-identity.amazonaws.com:amr": unauthenticated
  RoleAttachment:
    Type: AWS::Cognito::IdentityPoolRoleAttachment
    Properties:
      IdentityPoolId: !Ref IdentityPool
      Roles:
        unauthenticated: !GetAtt UnauthRole.Arn
Outputs:
  PoolId:
    Value: !Ref IdentityPool
  UnauthRoleName:
    Value: !Ref UnauthRole
  UnauthRoleArn:
    Value: !GetAtt UnauthRole.Arn
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-wired IdentityPoolRoleAttachment produces GetCredentialsForIdentity results
    scoped to the exact deployed (unauthenticated) role ARN, not some emulator-fabricated one."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-ciprole-")
    pool_name = ctx.unique_name("sim2real-behav-pool-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "PoolName", "ParameterValue": pool_name}],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:check", "Value": CHECK},
        ],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    outputs = _stack_outputs(cfn, stack_name)
    pool_id = outputs["PoolId"]
    role_name = outputs["UnauthRoleName"]
    role_arn = outputs["UnauthRoleArn"]

    cognito = ctx.client("cognito-identity")
    roles = cognito.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert roles["Roles"]["unauthenticated"] == role_arn, (
        f"expected GetIdentityPoolRoles to report the CFN-attached unauthenticated role "
        f"{role_arn!r}, got {roles['Roles'].get('unauthenticated')!r}"
    )

    identity_id = cognito.get_id(IdentityPoolId=pool_id)["IdentityId"]
    # IAM role trust-policy propagation is eventually consistent (no fixed SLA), so poll for it
    # rather than asserting immediately: https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    credentials = _wait_for_credentials(cognito, identity_id)

    role_sts = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": credentials["AccessKeyId"],
            "aws_secret_access_key": credentials["SecretKey"],
            "aws_session_token": credentials["SessionToken"],
        },
    )
    caller = role_sts.get_caller_identity()
    assert f"assumed-role/{role_name}/" in caller["Arn"], (
        f"expected GetCredentialsForIdentity to vend a session for the CFN-attached role "
        f"{role_name!r}, but GetCallerIdentity returned {caller['Arn']!r}"
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


def _wait_for_credentials(cognito, identity_id, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cognito.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"GetCredentialsForIdentity never succeeded (IAM role propagation?): {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
