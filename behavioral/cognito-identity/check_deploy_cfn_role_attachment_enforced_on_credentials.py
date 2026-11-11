"""deploy-cfn-role-attachment-enforced-on-credentials."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-role-attachment-enforced-on-credentials"
GROUP = "deploy"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation IdentityPoolRoleAttachment is enforced: GetCredentialsForIdentity vends
    credentials for the exact unauthenticated role it wired, matching GetIdentityPoolRoles."""
    cog = ctx.client("cognito-identity")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

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
                },
                "UnauthRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                                    "Action": "sts:AssumeRoleWithWebIdentity",
                                    "Condition": {
                                        "StringEquals": {
                                            "cognito-identity.amazonaws.com:aud": {"Ref": "IdentityPool"}
                                        },
                                        "ForAnyValue:StringLike": {
                                            "cognito-identity.amazonaws.com:amr": "unauthenticated"
                                        },
                                    },
                                }
                            ],
                        }
                    },
                },
                "RoleAttachment": {
                    "Type": "AWS::Cognito::IdentityPoolRoleAttachment",
                    "Properties": {
                        "IdentityPoolId": {"Ref": "IdentityPool"},
                        "Roles": {"unauthenticated": {"Fn::GetAtt": ["UnauthRole", "Arn"]}},
                    },
                },
            },
            "Outputs": {
                "IdentityPoolId": {"Value": {"Ref": "IdentityPool"}},
                "RoleArn": {"Value": {"Fn::GetAtt": ["UnauthRole", "Arn"]}},
                "RoleName": {"Value": {"Ref": "UnauthRole"}},
            },
        }
    )

    outputs = _deploy_stack(ctx, stack_name, template, capabilities=["CAPABILITY_IAM"])
    pool_id = outputs["IdentityPoolId"]
    role_arn = outputs["RoleArn"]
    role_name = outputs["RoleName"]

    identity_id = cog.get_id(IdentityPoolId=pool_id)["IdentityId"]

    creds = _get_credentials_with_retry(cog, identity_id)

    caller_sts = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    caller = caller_sts.get_caller_identity()
    partition = (
        "aws-cn" if ctx.region.startswith("cn-")
        else "aws-us-gov" if ctx.region.startswith("us-gov-")
        else "aws"
    )
    m = re.match(rf"^arn:{partition}:sts::(\d+):assumed-role/([^/]+)/.+$", caller["Arn"])
    assert m is not None, f"expected an assumed-role STS ARN from vended creds, got {caller['Arn']!r}"
    assert m.group(1) == account_id, f"vended creds resolved to account {m.group(1)!r}, expected {account_id!r}"
    assert m.group(2) == role_name, f"vended creds assumed role {m.group(2)!r}, expected the wired unauthenticated role {role_name!r}"

    roles = cog.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert roles["Roles"]["unauthenticated"] == role_arn, (
        f"GetIdentityPoolRoles reports unauthenticated={roles['Roles'].get('unauthenticated')!r}, "
        f"expected the CFN-deployed role {role_arn!r}"
    )


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
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_stack(cfn, stack_name, "stack_create_complete")
    return _stack_outputs(cfn, stack_name)


def _get_credentials_with_retry(cog, identity_id: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> dict:
    """New IAM roles can take a few seconds to propagate before
    AssumeRoleWithWebIdentity succeeds; poll for the observable success."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return cog.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            time.sleep(interval_s)
    raise AssertionError(f"get_credentials_for_identity never succeeded (last error={last_code})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
