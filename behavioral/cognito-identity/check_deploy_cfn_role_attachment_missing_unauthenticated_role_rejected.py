"""deploy-cfn-role-attachment-missing-unauthenticated-role-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-role-attachment-missing-unauthenticated-role-rejected"
GROUP = "deploy"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With a CFN role attachment wiring only an authenticated role, GetCredentialsForIdentity
    fails with InvalidIdentityPoolConfigurationException and no unauthenticated role is listed;
    attaching one via SetIdentityPoolRoles lets the same identity get credentials."""
    cog = ctx.client("cognito-identity")
    iam = ctx.client("iam")

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
                "AuthRole": {
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
                                            "cognito-identity.amazonaws.com:amr": "authenticated"
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
                        "Roles": {"authenticated": {"Fn::GetAtt": ["AuthRole", "Arn"]}},
                    },
                },
            },
            "Outputs": {"IdentityPoolId": {"Value": {"Ref": "IdentityPool"}}},
        }
    )

    outputs = _deploy_stack(ctx, stack_name, template, capabilities=["CAPABILITY_IAM"])
    pool_id = outputs["IdentityPoolId"]

    identity_id = cog.get_id(IdentityPoolId=pool_id)["IdentityId"]

    # (a) the specific error code
    err = _error(lambda: cog.get_credentials_for_identity(IdentityId=identity_id))
    expected = (
        "InvalidIdentityPoolConfigurationException",
        "Invalid identity pool configuration. Check assigned IAM roles for this pool.",
    )
    assert err == expected, (
        f"expected {expected!r} for a pool with no unauthenticated role wired, got {err!r}"
    )

    # (b) the effect is absent: no "unauthenticated" role is resolvable on the pool
    roles = cog.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert "unauthenticated" not in roles.get("Roles", {}), (
        f"expected no 'unauthenticated' entry in GetIdentityPoolRoles, got {roles.get('Roles', {})}"
    )

    # (c) positive control in the SAME file: wire an unauthenticated role directly
    # and confirm the very same identity can now get credentials.
    unauth_role_arn = _create_unauth_role(ctx, iam, pool_id)
    cog.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": unauth_role_arn})

    creds = _get_credentials_with_retry(cog, identity_id)
    assert creds["AccessKeyId"], f"expected a non-empty AccessKeyId, got {creds!r}"
    assert creds["SecretKey"], f"expected a non-empty SecretKey, got {creds!r}"
    assert creds["SessionToken"], f"expected a non-empty SessionToken, got {creds!r}"

    roles_after = cog.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert roles_after["Roles"]["unauthenticated"] == unauth_role_arn, (
        f"expected GetIdentityPoolRoles unauthenticated={unauth_role_arn!r} after "
        f"SetIdentityPoolRoles, got {roles_after['Roles'].get('unauthenticated')!r}"
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
    kwargs = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    if capabilities:
        kwargs["Capabilities"] = capabilities
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_stack(cfn, stack_name, "stack_create_complete")
    return _stack_outputs(cfn, stack_name)


def _create_unauth_role(ctx, iam, pool_id: str) -> str:
    role_name = ctx.unique_name("sim2real-unauth-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"},
                },
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


def _error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _get_credentials_with_retry(cog, identity_id: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> dict:
    """New IAM roles/role-mapping changes can take a few seconds to propagate
    before AssumeRoleWithWebIdentity succeeds; poll for the observable success."""
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
