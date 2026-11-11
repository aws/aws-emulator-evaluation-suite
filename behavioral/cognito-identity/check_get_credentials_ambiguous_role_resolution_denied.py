"""get-credentials-ambiguous-role-resolution-denied."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-credentials-ambiguous-role-resolution-denied"
GROUP = "overly-permissive"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Rules role mapping with AmbiguousRoleResolution=Deny and no matching rule rejects
    GetCredentialsForIdentity; flipping only that to AuthenticatedRole vends credentials
    for the authenticated role."""
    region = ctx.region
    cidp = ctx.client("cognito-idp")
    identity = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    # --- real Cognito user pool + confirmed user, used as the authenticated IdP ---
    pool_id, client_id, username, password = _create_confirmed_user_pool_user(ctx, cidp)
    provider_name = f"cognito-idp.{region}.amazonaws.com/{pool_id}"

    auth = cidp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]

    ci_pool_id = identity.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-cipool-"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": client_id, "ServerSideTokenCheck": False}
        ],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: identity.delete_identity_pool(IdentityPoolId=ci_pool_id))

    role_name, role_arn = _create_authenticated_role(ctx, iam, ci_pool_id)

    role_mapping_key = f"{provider_name}:{client_id}"
    rules_config = {
        "Rules": [
            {
                "Claim": "email",
                "MatchType": "Equals",
                "Value": "never-matches-xyz@example.com",
                "RoleARN": role_arn,
            }
        ]
    }

    identity.set_identity_pool_roles(
        IdentityPoolId=ci_pool_id,
        Roles={"authenticated": role_arn},
        RoleMappings={
            role_mapping_key: {
                "Type": "Rules",
                "AmbiguousRoleResolution": "Deny",
                "RulesConfiguration": rules_config,
            }
        },
    )

    logins = {provider_name: id_token}
    identity_id = identity.get_id(IdentityPoolId=ci_pool_id, Logins=logins)["IdentityId"]

    err = _client_error(
        lambda: identity.get_credentials_for_identity(IdentityId=identity_id, Logins=logins)
    )
    assert err == ("NotAuthorizedException", f"The ambiguous role mapping rules for: {provider_name} denied this request."), (
        f"expected NotAuthorizedException for a Deny-resolved, non-matching login, got {err!r}"
    )

    # positive control: only the AmbiguousRoleResolution changed, same non-matching rule
    identity.set_identity_pool_roles(
        IdentityPoolId=ci_pool_id,
        Roles={"authenticated": role_arn},
        RoleMappings={
            role_mapping_key: {
                "Type": "Rules",
                "AmbiguousRoleResolution": "AuthenticatedRole",
                "RulesConfiguration": rules_config,
            }
        },
    )

    creds = _poll_get_credentials(identity, identity_id, logins, timeout_s=30.0)["Credentials"]
    assert creds["AccessKeyId"], f"credentials empty after restore: {creds!r}"

    # Independent read at a different service: the vended keys must actually let us call STS,
    # and the assumed identity must be the mapped role, not just a truthy-looking response.
    caller_arn = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    ).get_caller_identity()["Arn"]
    assert f":assumed-role/{role_name}/" in caller_arn, (
        f"expected credentials assuming {role_name!r}, got caller identity {caller_arn!r}"
    )


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the ClientError's (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected GetCredentialsForIdentity to be denied for a Deny-resolved, non-matching "
        f"login, but it SUCCEEDED and returned {result!r}"
    )


def _create_confirmed_user_pool_user(ctx, cidp: Any) -> tuple[str, str, str, str]:
    pool_id = cidp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-userpool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cidp.delete_user_pool(UserPoolId=pool_id))

    client_id = cidp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2realuser")
    password = "TestPassw0rd1"
    cidp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    cidp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    return pool_id, client_id, username, password


def _create_authenticated_role(ctx, iam: Any, ci_pool_id: str) -> tuple[str, str]:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": ci_pool_id},
                    "ForAnyValue:StringLike": {
                        "cognito-identity.amazonaws.com:amr": "authenticated"
                    },
                },
            }
        ],
    }
    role_name = ctx.unique_name("sim2real-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_name, role_arn


def _poll_get_credentials(identity: Any, identity_id: str, logins: dict, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return identity.get_credentials_for_identity(IdentityId=identity_id, Logins=logins)
        except ClientError as err:
            last_err = err
            time.sleep(2.0)
    raise AssertionError(f"credentials never issued after role-mapping fallback: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
