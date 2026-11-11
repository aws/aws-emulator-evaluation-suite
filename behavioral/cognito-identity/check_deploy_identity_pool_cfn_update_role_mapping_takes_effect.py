"""deploy-identity-pool-cfn-update-role-mapping-takes-effect."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-identity-pool-cfn-update-role-mapping-takes-effect"
GROUP = "deploy"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """Updating the CFN stack's role mapping (unauthenticated: RoleA -> RoleB) changes which IAM
    role GetCredentialsForIdentity vends for the SAME identity, proving the managed resource's
    live behavior tracks stack updates rather than freezing the role at creation time."""
    pool_name = ctx.unique_name("sim2real_cog_pool_")

    def _template(active_role: str) -> str:
        return f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  IdentityPool:
    Type: AWS::Cognito::IdentityPool
    Properties:
      IdentityPoolName: {pool_name}
      AllowUnauthenticatedIdentities: true
  RoleA:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Federated: cognito-identity.amazonaws.com
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringEquals:
                cognito-identity.amazonaws.com:aud: !Ref IdentityPool
              "ForAnyValue:StringLike":
                cognito-identity.amazonaws.com:amr: unauthenticated
      Policies:
        - PolicyName: AllowGetCallerIdentity
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: sts:GetCallerIdentity
                Resource: '*'
  RoleB:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Federated: cognito-identity.amazonaws.com
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringEquals:
                cognito-identity.amazonaws.com:aud: !Ref IdentityPool
              "ForAnyValue:StringLike":
                cognito-identity.amazonaws.com:amr: unauthenticated
      Policies:
        - PolicyName: AllowGetCallerIdentity
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: sts:GetCallerIdentity
                Resource: '*'
  RoleAttachment:
    Type: AWS::Cognito::IdentityPoolRoleAttachment
    Properties:
      IdentityPoolId: !Ref IdentityPool
      Roles:
        unauthenticated: !GetAtt {active_role}.Arn
Outputs:
  IdentityPoolIdOut:
    Value: !Ref IdentityPool
  RoleANameOut:
    Value: !Ref RoleA
  RoleBNameOut:
    Value: !Ref RoleB
"""

    deployed = _deploy_cfn(ctx, _template("RoleA"))
    outputs = deployed["outputs"]
    pool_id = outputs["IdentityPoolIdOut"]
    role_a_name = outputs["RoleANameOut"]
    role_b_name = outputs["RoleBNameOut"]
    stack_name = deployed["stack_name"]

    cognito = ctx.client("cognito-identity")

    roles_before = cognito.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert role_a_name in roles_before["Roles"]["unauthenticated"], (
        f"expected the deployed unauthenticated role {role_a_name!r} in "
        f"{roles_before['Roles']['unauthenticated']!r}"
    )

    identity_id = cognito.get_id(IdentityPoolId=pool_id)["IdentityId"]

    creds_a = _poll_until(
        lambda: _try_get_credentials(cognito, identity_id),
        lambda c: c is not None,
        timeout_s=90,
        interval_s=5.0,
        description="initial GetCredentialsForIdentity resolves RoleA",
    )
    caller_a = _sts_client_from_credentials(ctx, creds_a).get_caller_identity()
    assert role_a_name in caller_a["Arn"], (
        f"expected the vended session to assume {role_a_name!r}, got {caller_a['Arn']!r}"
    )

    _update_cfn_and_wait(ctx, stack_name, _template("RoleB"))

    roles_after = cognito.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert role_b_name in roles_after["Roles"]["unauthenticated"], (
        f"expected the CFN update to move the unauthenticated role to {role_b_name!r}, got "
        f"{roles_after['Roles']['unauthenticated']!r}"
    )

    def _resolves_role_b():
        creds = _try_get_credentials(cognito, identity_id)
        if creds is None:
            return None
        caller = _sts_client_from_credentials(ctx, creds).get_caller_identity()
        return caller if role_b_name in caller["Arn"] else None

    caller_b = _poll_until(
        _resolves_role_b,
        lambda c: c is not None,
        timeout_s=90,
        interval_s=5.0,
        description="post-update GetCredentialsForIdentity resolves RoleB for the same identity",
    )
    assert role_b_name in caller_b["Arn"], (
        f"expected the post-update session to assume {role_b_name!r}, got {caller_b['Arn']!r}"
    )
    assert role_a_name not in caller_b["Arn"], (
        f"post-update session still resolved the old role {role_a_name!r}: {caller_b['Arn']!r}"
    )


def _try_get_credentials(cognito, identity_id):
    try:
        return cognito.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
    except ClientError:
        return None


_XSVC_PREFIX = "sim2real-xsvc-"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xname(ctx, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _xsvc_tags_kv():
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")},
    ]


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0):
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _update_cfn_and_wait(ctx, stack_name, template, *, timeout_s=300.0):
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=template,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack update {stack_name}",
    )
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    if stack["StackStatus"] != "UPDATE_COMPLETE":
        raise AssertionError(f"Stack update ended in {stack['StackStatus']}")
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _sts_client_from_credentials(ctx, creds):
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
