"""get-principal-tag-attribute-map-allowlist-mode-filters-claims."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-principal-tag-attribute-map-allowlist-mode-filters-claims"
GROUP = "data-plane"
SERVICES = ["cognito-identity"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetPrincipalTagAttributeMap returns the allow-list mapping (UseDefaults=False, AllowedTag
    from email), and the vended session calls GetCallerIdentity under a role that requires
    AllowedTag=<email> and denies any aud tag, so the default aud tag is not added."""
    region = ctx.region
    cidp = ctx.client("cognito-idp")
    ci = ctx.client("cognito-identity")
    iam = ctx.client("iam")

    pool_id, client_id = _create_user_pool_client(ctx, cidp)
    provider_name = f"cognito-idp.{region}.amazonaws.com/{pool_id}"
    email = f"{ctx.unique_name('sim2real-behav-allow-')}@example.com"
    id_token = _create_confirmed_user_id_token(ctx, cidp, pool_id, client_id, email)

    identity_pool = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-behav-pool-"),
        AllowUnauthenticatedIdentities=False,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": client_id, "ServerSideTokenCheck": False}
        ],
        IdentityPoolTags={"sim2real": CHECK},
    )
    pool_id_ci = identity_pool["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id_ci))

    # Allow-list: only the "email" claim is promoted, renamed to the "AllowedTag" principal tag.
    ci.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id_ci,
        IdentityProviderName=provider_name,
        UseDefaults=False,
        PrincipalTags={"AllowedTag": "email"},
    )
    mapping = ci.get_principal_tag_attribute_map(IdentityPoolId=pool_id_ci, IdentityProviderName=provider_name)
    assert (mapping.get("UseDefaults"), mapping.get("PrincipalTags")) == (False, {"AllowedTag": "email"}), (
        f"expected the allow-list mapping back from GetPrincipalTagAttributeMap, got {mapping!r}"
    )

    # A single sts:GetCallerIdentity call whose Allow/Deny both hinge on the tag set: it can only
    # succeed if AllowedTag=<email> IS present AND the default "aud" tag (which UseDefaults=True
    # would populate from the token's aud claim) is NOT present.
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyIfDefaultAudTagLeakedThrough",
                "Effect": "Deny",
                "Action": "sts:GetCallerIdentity",
                "Resource": "*",
                "Condition": {"StringLike": {"aws:PrincipalTag/aud": "*"}},
            },
            {
                "Sid": "AllowOnlyIfAllowedTagPresent",
                "Effect": "Allow",
                "Action": "sts:GetCallerIdentity",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalTag/AllowedTag": email}},
            },
        ],
    }
    role_arn, _role_name = _create_cognito_role(ctx, iam, pool_id_ci, inline_policy=inline_policy)
    ci.set_identity_pool_roles(IdentityPoolId=pool_id_ci, Roles={"authenticated": role_arn})

    logins = {provider_name: id_token}
    identity_id = ci.get_id(IdentityPoolId=pool_id_ci, Logins=logins)["IdentityId"]
    creds = _retry_get_credentials(ctx, identity_id, logins=logins)["Credentials"]

    vended = ctx.client(
        "sts",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    identity = vended.get_caller_identity()
    assert identity["Arn"], (
        "vended credentials could not call GetCallerIdentity -- either AllowedTag was missing/"
        "wrong, or a default (non-allow-listed) tag such as aud leaked through"
    )


def _create_user_pool_client(ctx, cidp):
    pool = cidp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-up-"),
        UserPoolTags={"sim2real": CHECK},
    )
    pool_id = pool["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cidp.delete_user_pool(UserPoolId=pool_id))
    client = cidp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-upc-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )
    client_id = client["UserPoolClient"]["ClientId"]
    return pool_id, client_id


def _create_confirmed_user_id_token(ctx, cidp, pool_id, client_id, email_value):
    username = ctx.unique_name("sim2real-behav-user-")
    password = "Sim2Real-Pass-1!"
    cidp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "email", "Value": email_value},
            {"Name": "email_verified", "Value": "true"},
        ],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    cidp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    auth = cidp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["IdToken"]


def _create_cognito_role(ctx, iam, pool_id, inline_policy=None):
    name = ctx.unique_name("sim2real-behav-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
