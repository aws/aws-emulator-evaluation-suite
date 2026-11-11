"""server-side-role-resolution-authenticated-vs-unauthenticated."""
from __future__ import annotations

import json
import time
import uuid

from botocore.config import Config

from behavioral_harness import tags

CHECK = "server-side-role-resolution-authenticated-vs-unauthenticated"
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

def _create_user_pool_login(ctx):
    """Create a real Cognito User Pool + app client + confirmed user and return an id token.

    Returns {provider_name, client_id, id_token}. A genuine, AWS-validated login token is the only
    self-contained way to exercise a real federated identity end to end against real AWS.
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


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetCredentialsForIdentity vends a session of the unauthenticated role for an anonymous
    identity and of the authenticated role for a federated identity, as STS GetCallerIdentity on
    each set of credentials shows."""
    ev = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    login = _create_user_pool_login(ctx)
    pool_id = _create_pool(
        ev, ctx, allow_unauth=True,
        CognitoIdentityProviders=[
            {"ProviderName": login["provider_name"], "ClientId": login["client_id"], "ServerSideTokenCheck": False}
        ],
    )
    auth_role_arn = _role_arn(iam, ctx, pool_id, "auth")
    unauth_role_arn = _role_arn(iam, ctx, pool_id, "unauth")
    ev.set_identity_pool_roles(
        IdentityPoolId=pool_id,
        Roles={"authenticated": auth_role_arn, "unauthenticated": unauth_role_arn},
    )

    anon_identity_id = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    logins = {login["provider_name"]: login["id_token"]}
    auth_identity_id = ev.get_id(IdentityPoolId=pool_id, Logins=logins)["IdentityId"]
    assert anon_identity_id != auth_identity_id, (
        f"expected the anonymous GetId call and the federated GetId call to resolve to distinct "
        f"identities, but both returned {anon_identity_id!r}"
    )

    token_resp = ev.get_open_id_token(IdentityId=auth_identity_id, Logins=logins)
    assert token_resp["IdentityId"] == auth_identity_id, (
        f"expected GetOpenIdToken to echo the federated IdentityId {auth_identity_id!r}, got "
        f"{token_resp['IdentityId']!r}"
    )
    assert token_resp.get("Token"), (
        f"expected GetOpenIdToken to return a non-empty Token, got {token_resp.get('Token')!r}"
    )

    def _get_creds(identity_id, call_logins):
        def _try():
            try:
                kwargs = {"IdentityId": identity_id}
                if call_logins:
                    kwargs["Logins"] = call_logins
                return ev.get_credentials_for_identity(**kwargs)
            except Exception as exc:  # noqa: BLE001 -- role/trust-policy propagation lag
                return exc

        return _poll_until(
            _try, lambda r: not isinstance(r, Exception), timeout_s=45, interval_s=3.0,
            description="newly configured identity pool roles become usable",
        )

    unauth_role_name = unauth_role_arn.split("/")[-1]
    auth_role_name = auth_role_arn.split("/")[-1]

    unauth_creds = _get_creds(anon_identity_id, None)["Credentials"]
    unauth_arn = _sts_client_from_credentials(ctx, unauth_creds).get_caller_identity()["Arn"]
    assert unauth_role_name in unauth_arn, (
        f"expected the anonymous identity's credentials to assume the unauthenticated role "
        f"{unauth_role_arn}, but STS GetCallerIdentity reports {unauth_arn}"
    )
    assert auth_role_name not in unauth_arn, (
        f"expected the anonymous identity's STS ARN {unauth_arn!r} to NOT reference the "
        f"authenticated role {auth_role_name!r}"
    )

    auth_creds = _get_creds(auth_identity_id, logins)["Credentials"]
    auth_arn = _sts_client_from_credentials(ctx, auth_creds).get_caller_identity()["Arn"]
    assert auth_role_name in auth_arn, (
        f"expected the federated identity's credentials to assume the authenticated role "
        f"{auth_role_arn}, but STS GetCallerIdentity reports {auth_arn}"
    )
    assert unauth_role_name not in auth_arn, (
        f"expected the federated identity's STS ARN {auth_arn!r} to NOT reference the "
        f"unauthenticated role {unauth_role_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
