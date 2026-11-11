"""get-identity-pool-roles-rules-based-mapping-selects-role-by-claim."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-identity-pool-roles-rules-based-mapping-selects-role-by-claim"
GROUP = "data-plane"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With a rules-based RoleMapping configured, GetCredentialsForIdentity selects the specific
    role whose rule matches the identity's login claim, and falls back to the default role for an
    identity whose claim does not match any rule."""
    ci = ctx.client("cognito-identity")

    pool_id, client_id, provider_name = _create_user_pool_client(ctx)

    email_match = f"{ctx.unique_name('sim2real-behav-match-')}@example.com"
    email_other = f"{ctx.unique_name('sim2real-behav-other-')}@example.com"
    token_match = _create_confirmed_user_id_token(ctx, pool_id, client_id, email_match)
    token_other = _create_confirmed_user_id_token(ctx, pool_id, client_id, email_other)

    identity_pool = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": client_id, "ServerSideTokenCheck": False}
        ],
        IdentityPoolTags={"sim2real": CHECK},
    )
    identity_pool_id = identity_pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=identity_pool_id))

    default_role_arn, default_role_name = _create_cognito_role(ctx, identity_pool_id, authenticated=True)
    matched_role_arn, matched_role_name = _create_cognito_role(ctx, identity_pool_id, authenticated=True)

    # NB: per SetIdentityPoolRoles docs, the RoleMappings key for a Cognito User Pool provider
    # must be "<provider_name>:<app_client_id>" (unlike CognitoIdentityProviders'
    # ProviderName, which has no client-id suffix); a bare provider_name key is rejected as
    # "not a valid RoleMapping ProviderName or is not a configured provider".
    role_mapping_key = f"{provider_name}:{client_id}"

    ci.set_identity_pool_roles(
        IdentityPoolId=identity_pool_id,
        Roles={"authenticated": default_role_arn},
        RoleMappings={
            role_mapping_key: {
                "Type": "Rules",
                "AmbiguousRoleResolution": "AuthenticatedRole",
                "RulesConfiguration": {
                    "Rules": [
                        {"Claim": "email", "MatchType": "Equals", "Value": email_match, "RoleARN": matched_role_arn},
                    ]
                },
            }
        },
    )
    roles = ci.get_identity_pool_roles(IdentityPoolId=identity_pool_id)
    stored_type = roles["RoleMappings"][role_mapping_key]["Type"]
    assert stored_type == "Rules", f"expected RoleMappings[{role_mapping_key!r}].Type == 'Rules', got {stored_type!r}"

    # Matching identity: must assume the rule-specific role.
    identity_match = ci.get_id(IdentityPoolId=identity_pool_id, Logins={provider_name: token_match})["IdentityId"]
    creds_match = _retry_get_credentials(ctx, identity_match, logins={provider_name: token_match})["Credentials"]
    arn_match = _vended_caller_arn(ctx, creds_match)
    assert f"assumed-role/{matched_role_name}/" in arn_match, (
        f"matching identity did not assume the rule-specific role: {arn_match!r}"
    )
    assert f"assumed-role/{default_role_name}/" not in arn_match, (
        f"matching identity must not fall back to the default role {default_role_name!r}: {arn_match!r}"
    )

    # Non-matching identity: must fall back to the default authenticated role.
    identity_other = ci.get_id(IdentityPoolId=identity_pool_id, Logins={provider_name: token_other})["IdentityId"]
    creds_other = _retry_get_credentials(ctx, identity_other, logins={provider_name: token_other})["Credentials"]
    arn_other = _vended_caller_arn(ctx, creds_other)
    assert f"assumed-role/{default_role_name}/" in arn_other, (
        f"non-matching identity did not fall back to the default role: {arn_other!r}"
    )
    assert f"assumed-role/{matched_role_name}/" not in arn_other, (
        f"non-matching identity must not assume the rule-specific role {matched_role_name!r}: {arn_other!r}"
    )


def _create_user_pool_client(ctx):
    idp = ctx.client("cognito-idp")
    pool = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-up-"),
        UserPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-upc-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )
    client_id = client["UserPoolClient"]["ClientId"]
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"
    return pool_id, client_id, provider_name


def _create_confirmed_user_id_token(ctx, pool_id, client_id, email_value):
    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-behav-user-")
    password = "Sim2Real-Pass-1!"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": email_value},
            {"Name": "email_verified", "Value": "true"},
        ],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["IdToken"]


def _create_cognito_role(ctx, pool_id, authenticated, extra_conditions=None, inline_policy=None):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    amr = "authenticated" if authenticated else "unauthenticated"
    string_equals = {"cognito-identity.amazonaws.com:aud": pool_id}
    if extra_conditions:
        string_equals.update(extra_conditions)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
                "Condition": {
                    "StringEquals": string_equals,
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
                },
            }
        ],
    }
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if inline_policy:
        iam.put_role_policy(RoleName=name, PolicyName="sim2real-inline", PolicyDocument=json.dumps(inline_policy))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="sim2real-inline"))
    return role_arn, name


def _retry_get_credentials(ctx, identity_id, logins=None, timeout_s=90.0, interval_s=5.0):
    ci = ctx.client("cognito-identity")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            kwargs = {"IdentityId": identity_id}
            if logins:
                kwargs["Logins"] = logins
            return ci.get_credentials_for_identity(**kwargs)
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"GetCredentialsForIdentity never succeeded within {timeout_s}s: {last_exc}")


def _vended_caller_arn(ctx, creds):
    vended = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return vended.get_caller_identity()["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
