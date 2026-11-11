"""deploy-identity-pool-cfn-stack-behaves."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-identity-pool-cfn-stack-behaves"
GROUP = "deploy"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An identity pool and role attachment deployed by CloudFormation describe as templated, and
    GetId plus GetCredentialsForIdentity vend a session of the template's unauthenticated role, so
    the stack works beyond CREATE_COMPLETE."""
    pool_name = ctx.unique_name("sim2real_cog_pool_")
    template = f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  IdentityPool:
    Type: AWS::Cognito::IdentityPool
    Properties:
      IdentityPoolName: {pool_name}
      AllowUnauthenticatedIdentities: true
  UnauthRole:
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
        unauthenticated: !GetAtt UnauthRole.Arn
Outputs:
  IdentityPoolIdOut:
    Value: !Ref IdentityPool
  UnauthRoleArnOut:
    Value: !GetAtt UnauthRole.Arn
  UnauthRoleNameOut:
    Value: !Ref UnauthRole
"""
    deployed = _deploy_cfn(ctx, template)
    outputs = deployed["outputs"]
    pool_id = outputs["IdentityPoolIdOut"]
    role_arn = outputs["UnauthRoleArnOut"]
    role_name = outputs["UnauthRoleNameOut"]

    cognito = ctx.client("cognito-identity")

    desc = cognito.describe_identity_pool(IdentityPoolId=pool_id)
    assert desc["IdentityPoolId"] == pool_id, f"expected pool id {pool_id!r}, got {desc['IdentityPoolId']!r}"
    assert desc["AllowUnauthenticatedIdentities"] is True, (
        f"expected AllowUnauthenticatedIdentities True, got {desc['AllowUnauthenticatedIdentities']!r}"
    )

    roles = cognito.get_identity_pool_roles(IdentityPoolId=pool_id)
    assert roles["Roles"]["unauthenticated"] == role_arn, (
        f"expected unauthenticated role {role_arn!r}, got {roles['Roles'].get('unauthenticated')!r}"
    )

    identity_id = cognito.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert identity_id, "GetId returned an empty IdentityId"

    # IAM role trust-policy propagation can lag a few seconds behind CREATE_COMPLETE.
    creds = _poll_until(
        lambda: _try_get_credentials(cognito, identity_id),
        lambda c: c is not None,
        timeout_s=90,
        interval_s=5.0,
        description="GetCredentialsForIdentity resolves the CFN-configured role",
    )
    sts_as_identity = _sts_client_from_credentials(ctx, creds)
    caller = sts_as_identity.get_caller_identity()
    assert role_name in caller["Arn"], f"expected role {role_name!r} in {caller['Arn']!r}"
    assert ":assumed-role/" in caller["Arn"], f"expected an assumed-role ARN, got {caller['Arn']!r}"


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
