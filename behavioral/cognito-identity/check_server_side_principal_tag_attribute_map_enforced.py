"""server-side-principal-tag-attribute-map-enforced."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-principal-tag-attribute-map-enforced"
GROUP = 'credentials'
SERVICES = ['cognito-identity']

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK}, **kwargs
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

def _cognito_trust_policy(pool_id: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id}},
            }
        ],
    }

def _role_arn(iam_client, ctx, pool_id, slot="auth"):
    """Create a real IAM role Cognito Identity can pass; register delete cleanup; return its ARN."""
    role_name = f"sim2real-behav-role-{slot}-{uuid.uuid4().hex[:8]}"[:60]
    arn = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_cognito_trust_policy(pool_id)),
        Description="sim2real behavioral probe role for Cognito Identity",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam_client.delete_role(RoleName=role_name))
    return arn

def _role_arn_with_actions(iam_client, ctx, pool_id, actions, authenticated=True, slot="role"):
    """Like _role_arn but lets the caller control exactly which STS actions the trust policy grants
    the federated principal (e.g. including/excluding sts:TagSession to prove principal-tag
    enforcement)."""
    amr = "authenticated" if authenticated else "unauthenticated"
    role_name = f"sim2real-behav-role-{slot}-{uuid.uuid4().hex[:8]}"[:60]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": actions,
                "Condition": {
                    "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                    "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": amr},
                },
            }
        ],
    }
    arn = iam_client.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam_client.delete_role(RoleName=role_name))
    return arn

def _create_user_pool_login(ctx):
    """Create a real Cognito User Pool + app client + confirmed user and return an id token.

    Cognito Identity rejects fabricated tokens for real login-provider domains, so a Cognito User
    Pool JWT is the only self-contained way to exercise a genuine federated (non-anonymous,
    non-developer) login end to end against real AWS. Returns {provider_name, client_id, id_token}.
    """
    idp = ctx.client("cognito-idp")
    up = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-userpool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    user_pool_id = up["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=user_pool_id))
    client_resp = idp.create_user_pool_client(
        UserPoolId=user_pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )
    client_id = client_resp["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-behav-user-")
    password = "Sim2Real-Behav-Pw1!"
    idp.admin_create_user(
        UserPoolId=user_pool_id, Username=username, TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    idp.admin_set_user_password(
        UserPoolId=user_pool_id, Username=username, Password=password, Permanent=True
    )
    auth = idp.admin_initiate_auth(
        UserPoolId=user_pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"
    return {"provider_name": provider_name, "client_id": client_id, "id_token": id_token}

def _poll_until(fn, pred, timeout_s=45, interval_s=3.0, description="condition"):
    """Poll fn() until pred(result) is truthy or the deadline passes; returns the last result."""
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = fn()
        if pred(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"poll condition not met within {timeout_s}s ({description}): {result!r}")

def _sts_client_from_credentials(ctx, creds):
    """A client on the target signed with the vended temporary credentials."""
    return ctx.client(
        "sts",
        config=Config(retries={"max_attempts": 1}),
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


@tags("axis:rejection", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With a PrincipalTags mapping set, GetCredentialsForIdentity is refused with
    InvalidIdentityPoolConfigurationException for a role whose trust policy lacks sts:TagSession,
    and vends a session of the role once it grants sts:TagSession, so the mapping reaches STS."""
    ev = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    login = _create_user_pool_login(ctx)
    provider_name = login["provider_name"]
    pool_id = _create_pool(
        ev, ctx, allow_unauth=True,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": login["client_id"], "ServerSideTokenCheck": False}
        ],
    )

    role_no_tag_session = _role_arn_with_actions(
        iam, ctx, pool_id, ["sts:AssumeRoleWithWebIdentity"], authenticated=True, slot="notag"
    )
    role_with_tag_session = _role_arn_with_actions(
        iam, ctx, pool_id, ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
        authenticated=True, slot="withtag",
    )
    unauth_role_arn = _role_arn(iam, ctx, pool_id, "unauth")

    ev.set_identity_pool_roles(
        IdentityPoolId=pool_id,
        Roles={"authenticated": role_no_tag_session, "unauthenticated": unauth_role_arn},
    )

    ev.set_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name,
        UseDefaults=False, PrincipalTags={"team": "sub"},
    )
    got = ev.get_principal_tag_attribute_map(
        IdentityPoolId=pool_id, IdentityProviderName=provider_name
    )
    assert got.get("PrincipalTags") == {"team": "sub"}, (
        f"expected GetPrincipalTagAttributeMap to reflect the mapping just set, got {got}"
    )
    assert got.get("UseDefaults") is False

    logins = {provider_name: login["id_token"]}
    identity_id = ev.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]

    def _try_creds():
        try:
            return ev.get_credentials_for_identity(IdentityId=identity_id, Logins=logins)
        except ClientError as exc:
            return exc

    # The role WITHOUT sts:TagSession is rejected while principal tags are configured, with the
    # error Cognito Identity documents for an STS-rejected AssumeRoleWithWebIdentity.
    denied = _poll_until(
        _try_creds, lambda r: isinstance(r, ClientError), timeout_s=30, interval_s=3.0,
        description="role lacking sts:TagSession rejected while PrincipalTags are configured",
    )
    denied_code = denied.response.get("Error", {}).get("Code")
    assert denied_code == "InvalidIdentityPoolConfigurationException", (
        "expected GetCredentialsForIdentity to fail with InvalidIdentityPoolConfigurationException "
        f"while PrincipalTags are configured but the assumed role's trust policy does not grant "
        f"sts:TagSession, got {denied_code!r} ({denied})"
    )
    denied_message = denied.response.get("Error", {}).get("Message")
    assert denied_message == "Invalid identity pool configuration. Check assigned IAM roles for this pool.", (
        f"expected the exact refusal message AWS returns, got {denied_message!r}"
    )

    # Swap in the role that DOES grant sts:TagSession -- the SAME config must now succeed.
    ev.set_identity_pool_roles(
        IdentityPoolId=pool_id,
        Roles={"authenticated": role_with_tag_session, "unauthenticated": unauth_role_arn},
    )
    allowed = _poll_until(
        _try_creds, lambda r: not isinstance(r, Exception), timeout_s=45, interval_s=3.0,
        description="role granting sts:TagSession becomes usable with PrincipalTags configured",
    )
    creds = allowed["Credentials"]
    arn = _sts_client_from_credentials(ctx, creds).get_caller_identity()["Arn"]
    assert role_with_tag_session.split("/")[-1] in arn, (
        f"expected credentials to assume the role granting sts:TagSession, got {arn}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
