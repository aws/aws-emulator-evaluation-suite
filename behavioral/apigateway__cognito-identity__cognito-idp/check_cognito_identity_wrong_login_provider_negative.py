"""cognito-identity-wrong-login-provider-negative."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cognito-identity-wrong-login-provider-negative"
GROUP = "overly-permissive"
SERVICES = ["apigateway", "cognito-identity", "cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetId rejects a token from a User Pool that is NOT registered as a login provider
    on the identity pool, and does not create a new identity for it; a token from the
    registered pool (the positive control) succeeds on the exact same identity pool."""
    pool_registered = _create_confirmed_user_pool(ctx, "sim2real-uidpr-")
    pool_unregistered = _create_confirmed_user_pool(ctx, "sim2real-uidpu-")

    identity_pool_id = _create_identity_pool(
        ctx,
        "sim2real-ipw-",
        providers=[
            {
                "ProviderName": pool_registered["provider_name"],
                "ClientId": pool_registered["client_id"],
                "ServerSideTokenCheck": False,
            }
        ],
    )
    cid = ctx.client("cognito-identity")

    before_count = len(
        cid.list_identities(IdentityPoolId=identity_pool_id, MaxResults=60)["Identities"]
    )

    bad_logins = {pool_unregistered["provider_name"]: pool_unregistered["id_token"]}
    code, message = _error(
        lambda: cid.get_id(IdentityPoolId=identity_pool_id, Logins=bad_logins)
    )
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException for a real, validly-signed token from a user pool "
        f"NOT registered as a login provider on this identity pool, got {code!r}"
    )
    expected_message = "Token is not from a supported provider of this identity pool."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_bad_count = len(
        cid.list_identities(IdentityPoolId=identity_pool_id, MaxResults=60)["Identities"]
    )
    assert after_bad_count == before_count, (
        f"rejected login must create no identity: before={before_count}, "
        f"after={after_bad_count}"
    )

    # Positive control: same identity pool, same call shape, with the REGISTERED provider.
    good_logins = {pool_registered["provider_name"]: pool_registered["id_token"]}
    resp = cid.get_id(IdentityPoolId=identity_pool_id, Logins=good_logins)
    assert resp["IdentityId"].startswith(f"{ctx.region}:"), (
        f"expected an IdentityId prefixed with {ctx.region!r}, got {resp['IdentityId']!r}"
    )

    after_good_count = len(
        cid.list_identities(IdentityPoolId=identity_pool_id, MaxResults=60)["Identities"]
    )
    assert after_good_count == before_count + 1, (
        f"the registered-provider token must mint exactly one identity: before={before_count}, "
        f"after={after_good_count}"
    )


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _create_confirmed_user_pool(ctx, name_prefix: str) -> dict:
    idp = ctx.client("cognito-idp")
    pool_name = ctx.unique_name(name_prefix)
    pool_id = idp.create_user_pool(
        PoolName=pool_name, UserPoolTags={"sim2real": CHECK}
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=pool_name + "-client",
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("user-")
    password = "Sim2Real1!Aa"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]
    provider_name = f"cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"
    return {
        "pool_id": pool_id,
        "client_id": client_id,
        "username": username,
        "id_token": id_token,
        "provider_name": provider_name,
    }


def _create_identity_pool(ctx, name_prefix: str, providers=None, allow_unauth: bool = False) -> str:
    cid = ctx.client("cognito-identity")
    name = ctx.unique_name(name_prefix)
    pool_id = cid.create_identity_pool(
        IdentityPoolName=name,
        AllowUnauthenticatedIdentities=allow_unauth,
        CognitoIdentityProviders=providers or [],
        IdentityPoolTags={"sim2real": CHECK},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: cid.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
