"""deploy-cognito-identity-pool-roles-stack-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cognito-identity-pool-roles-stack-positive"
GROUP = "deploy-behavior"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]

_TEST_PASSWORD = "Sim2Real!Test123"

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  UserPool:
    Type: AWS::Cognito::UserPool
    Properties:
      UserPoolName: {pool_name}
  UserPoolClient:
    Type: AWS::Cognito::UserPoolClient
    Properties:
      UserPoolId: !Ref UserPool
      ClientName: {client_name}
      GenerateSecret: false
      ExplicitAuthFlows:
        - ALLOW_ADMIN_USER_PASSWORD_AUTH
        - ALLOW_REFRESH_TOKEN_AUTH
  IdentityPool:
    Type: AWS::Cognito::IdentityPool
    Properties:
      IdentityPoolName: {identity_pool_name}
      AllowUnauthenticatedIdentities: false
      CognitoIdentityProviders:
        - ClientId: !Ref UserPoolClient
          ProviderName: !GetAtt UserPool.ProviderName
          ServerSideTokenCheck: false
  AuthenticatedRole:
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
                cognito-identity.amazonaws.com:aud: !Ref IdentityPool
              "ForAnyValue:StringLike":
                cognito-identity.amazonaws.com:amr: authenticated
  IdentityPoolRoleAttachment:
    Type: AWS::Cognito::IdentityPoolRoleAttachment
    Properties:
      IdentityPoolId: !Ref IdentityPool
      Roles:
        authenticated: !GetAtt AuthenticatedRole.Arn
      RoleMappings:
        cognitoProvider:
          Type: Token
          AmbiguousRoleResolution: AuthenticatedRole
          IdentityProvider: !Sub "cognito-idp.${{AWS::Region}}.amazonaws.com/${{UserPool}}:${{UserPoolClient}}"
Outputs:
  UserPoolId:
    Value: !Ref UserPool
  UserPoolClientId:
    Value: !Ref UserPoolClient
  IdentityPoolId:
    Value: !Ref IdentityPool
  RoleName:
    Value: !Ref AuthenticatedRole
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed Identity Pool whose RoleMappings reference a User Pool provider grants
    the mapped authenticated role's real STS credentials to a user who signs in through
    that pool (ambiguous-role fallback to the Roles.authenticated role)."""
    pool_name = _xname(ctx, "pool")
    client_name = _xname(ctx, "client")
    identity_pool_name = ctx.unique_name("sim2realxsvcidp").replace("-", "")
    template = _TEMPLATE.format(
        pool_name=pool_name, client_name=client_name, identity_pool_name=identity_pool_name
    )

    stack = _deploy_cfn(ctx, template)
    user_pool_id = stack["outputs"]["UserPoolId"]
    client_id = stack["outputs"]["UserPoolClientId"]
    identity_pool_id = stack["outputs"]["IdentityPoolId"]
    role_name = stack["outputs"]["RoleName"]

    id_token = _create_user_and_get_id_token(ctx, user_pool_id, client_id)
    region = ctx.region
    login_key = f"cognito-idp.{region}.amazonaws.com/{user_pool_id}"

    cid = ctx.client("cognito-identity")
    identity_id = cid.get_id(
        IdentityPoolId=identity_pool_id, Logins={login_key: id_token}
    )["IdentityId"]

    creds = _poll_until(
        lambda: _try_get_credentials(cid, identity_id, login_key, id_token),
        lambda result: result is not None,
        timeout_s=60.0,
        interval_s=3.0,
        description="get_credentials_for_identity to succeed (IAM role propagation)",
    )

    federated_sts = _sts_client_from_credentials(ctx, creds)
    identity = federated_sts.get_caller_identity()
    assert role_name in identity["Arn"], f"expected role {role_name!r} in {identity['Arn']!r}"
    assert ":assumed-role/" in identity["Arn"], f"expected an assumed-role ARN, got {identity['Arn']!r}"


def _sts_client_from_credentials(ctx, creds):
    return ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _try_get_credentials(cid, identity_id, login_key, id_token):
    try:
        resp = cid.get_credentials_for_identity(
            IdentityId=identity_id, Logins={login_key: id_token}
        )
        return resp["Credentials"]
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


def _xsvc_resource_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
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


def _create_user_and_get_id_token(ctx, user_pool_id: str, client_id: str) -> str:
    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-xsvc-user-")
    idp.admin_create_user(
        UserPoolId=user_pool_id,
        Username=username,
        TemporaryPassword=_TEST_PASSWORD,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=user_pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=user_pool_id, Username=username, Password=_TEST_PASSWORD, Permanent=True
    )
    auth = idp.admin_initiate_auth(
        UserPoolId=user_pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _TEST_PASSWORD},
    )
    return auth["AuthenticationResult"]["IdToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
