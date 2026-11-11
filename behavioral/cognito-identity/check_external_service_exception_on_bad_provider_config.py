"""external-service-exception-on-bad-provider-config."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "external-service-exception-on-bad-provider-config"
GROUP = 'error-semantics'
SERVICES = ['cognito-identity']

def _client_error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")

def _create_pool(client, ctx, allow_unauth=True, name_prefix="pool-", **kwargs):
    """CreateIdentityPool + register best-effort DeleteIdentityPool cleanup; returns the pool id."""
    name = f"sim2real-behav-{name_prefix}{uuid.uuid4().hex[:8]}".replace("-", "_")
    pool_id = client.create_identity_pool(
        IdentityPoolName=name, AllowUnauthenticatedIdentities=allow_unauth,
        IdentityPoolTags={"sim2real": CHECK}, **kwargs
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: client.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id

def _create_unauth_role(ctx, iam, pool_id):
    """A minimal role trusted for AssumeRoleWithWebIdentity, scoped to this pool's unauthenticated
    identities -- the restore leg for GetCredentialsForIdentity's InvalidIdentityPoolConfiguration
    refusal."""
    role_name = ctx.unique_name("sim2real-cog-unauth-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {"cognito-identity.amazonaws.com:aud": pool_id},
                "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"},
            },
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _user_pool_provider(ctx):
    """A Cognito user pool and app client this check owns: the login provider every target serves.

    Returns ``(provider_name, client_id)``; the provider name is the issuer host and path built
    from CreateUserPool's own answer, so no third-party identity provider is named or contacted.
    """
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-userpool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-client-"), GenerateSecret=False
    )["UserPoolClient"]["ClientId"]
    return f"cognito-idp.{ctx.region}.amazonaws.com/{pool_id}", client_id

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An invalid provider token is refused with NotAuthorizedException on GetId and GetOpenIdToken,
    and a pool with no roles refuses GetCredentialsForIdentity until an unauthenticated role is set;
    each refusal is paired with a positive control."""
    ev = ctx.client("cognito-identity")
    iam = ctx.client("iam")
    provider_name, client_id = _user_pool_provider(ctx)
    pool_id = _create_pool(
        ev, ctx, allow_unauth=True,
        CognitoIdentityProviders=[{"ProviderName": provider_name, "ClientId": client_id}],
    )

    # Positive control: this pool's anonymous flow works before anything is broken.
    identity_id = ev.get_id(IdentityPoolId=pool_id)["IdentityId"]
    assert identity_id, "GetId with no Logins must mint an identity for a healthy pool"

    # GetId: a login token for a *configured* provider that the provider itself
    # cannot validate (a garbage OAuth token) must be rejected.
    bad_logins = {provider_name: "not-a-real-user-pool-id-token"}
    err = _client_error(lambda: ev.get_id(IdentityPoolId=pool_id, Logins=bad_logins))
    assert err == ("NotAuthorizedException", "Invalid login token. Not a valid OpenId Connect identity token."), (
        f"expected NotAuthorizedException for GetId with a bad user pool token, got {err!r}"
    )

    # Positive control: the same identity's open-id-token path works before anything is broken.
    token = ev.get_open_id_token(IdentityId=identity_id)["Token"]
    assert token, "GetOpenIdToken must succeed for the identity's own anonymous flow"

    # GetOpenIdToken: an identity that never linked any login is asked to mint a
    # token while claiming a login it never established.
    err = _client_error(
        lambda: ev.get_open_id_token(IdentityId=identity_id, Logins=bad_logins)
    )
    assert err == ("NotAuthorizedException", "Invalid login token. Not a valid OpenId Connect identity token."), (
        f"expected NotAuthorizedException for GetOpenIdToken with a bad user pool token, got {err!r}"
    )

    # GetCredentialsForIdentity: this pool has NEVER had SetIdentityPoolRoles called.
    err = _client_error(lambda: ev.get_credentials_for_identity(IdentityId=identity_id))
    assert err == ("InvalidIdentityPoolConfigurationException", "Invalid identity pool configuration. Check assigned IAM roles for this pool."), (
        f"expected InvalidIdentityPoolConfigurationException for a pool with no roles configured, got {err!r}"
    )

    # Effect absent, via an independent read: the identity exists but was never vended credentials.
    described = ev.describe_identity(IdentityId=identity_id)
    assert described["IdentityId"] == identity_id, described

    # Restore: configure the unauthenticated role this identity is entitled to, and demand the
    # identical call now succeeds.
    role_arn = _create_unauth_role(ctx, iam, pool_id)
    ev.set_identity_pool_roles(IdentityPoolId=pool_id, Roles={"unauthenticated": role_arn})

    deadline = time.monotonic() + 60.0
    creds = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = ev.get_credentials_for_identity(IdentityId=identity_id)["Credentials"]
            break
        except ClientError as err:
            last_err = err.response.get("Error", {}).get("Code")
            time.sleep(3.0)
    assert creds is not None, (
        f"expected GetCredentialsForIdentity to succeed once roles were configured (last error: {last_err})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
