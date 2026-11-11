"""deep-cognito-identity-1-unsigned-public-api-unlink-identity-with-owned-logins-succeeds."""
from __future__ import annotations

import uuid

from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-identity-1-unsigned-public-api-unlink-identity-with-owned-logins-succeeds"
GROUP = "unsigned-public-api"
SERVICES = ["cognito-identity"]

# On real Cognito Identity, UnlinkIdentity is `auth: []`: an
# UNSIGNED request that carries a valid login for the identity SUCCEEDS. The unlinked identity is
# then projected with the sentinel Logins ["DISABLED"], and replaying the identical unlink is
# refused NotAuthorizedException ("Logins don't match ...").
DISABLED = "DISABLED"
ERR_NOT_AUTHORIZED = "NotAuthorizedException"
MSG_LOGINS_DONT_MATCH = (
    "Logins don't match. Please include at least one valid login for this identity or identity pool."
)


@tags(
    "dp:api",
    "plane:data",
    "concern:negative-classes",
    "concern:data-plane",
    "axis:happy-path",
    "cap:c1",
)
def run(ctx) -> None:
    """An unsigned UnlinkIdentity succeeds on proof of login ownership alone and drops the link:
    DescribeIdentity shows the DISABLED sentinel, a replay is refused, and the same login then
    resolves to a new identity."""
    signed = ctx.client("cognito-identity")
    unsigned = ctx.client("cognito-identity", config=Config(signature_version=UNSIGNED))

    idp, user_pool_id, client_id = _create_user_pool(ctx)
    provider = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"
    id_token = _mint_id_token(idp, ctx, user_pool_id, client_id)
    pool_id = _create_identity_pool(signed, ctx, provider, client_id)

    linked = unsigned.get_id(IdentityPoolId=pool_id, Logins={provider: id_token})["IdentityId"]
    before = signed.describe_identity(IdentityId=linked)
    assert before.get("Logins") == [provider], (
        f"after an unsigned GetId with Logins the identity lists {before.get('Logins')!r}, "
        f"expected exactly [{provider!r}]"
    )

    resp = unsigned.unlink_identity(
        IdentityId=linked, Logins={provider: id_token}, LoginsToRemove=[provider],
    )
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"unsigned UnlinkIdentity with owned Logins returned HTTP {status!r}"

    after = signed.describe_identity(IdentityId=linked)
    assert after["IdentityId"] == linked, f"DescribeIdentity echoed {after['IdentityId']!r}"
    assert after.get("Logins") == [DISABLED], (
        f"after the unsigned unlink the identity lists {after.get('Logins')!r}, expected the "
        f"sentinel [{DISABLED!r}]"
    )

    err = _error(lambda: unsigned.unlink_identity(
        IdentityId=linked, Logins={provider: id_token}, LoginsToRemove=[provider],
    ))
    assert (err.get("Code"), err.get("Message")) == (ERR_NOT_AUTHORIZED, MSG_LOGINS_DONT_MATCH), (
        f"replaying the unlink on the orphaned identity answered {err!r}, expected "
        f"{ERR_NOT_AUTHORIZED!r}: {MSG_LOGINS_DONT_MATCH!r}"
    )

    relinked = unsigned.get_id(IdentityPoolId=pool_id, Logins={provider: id_token})["IdentityId"]
    assert relinked != linked, (
        f"after the unlink the same login still resolves to {linked!r}; the link was not dropped"
    )
    fresh = signed.describe_identity(IdentityId=relinked)
    assert fresh.get("Logins") == [provider], (
        f"the re-linked identity {relinked!r} lists {fresh.get('Logins')!r}, expected [{provider!r}]"
    )


# ===== helpers =====

def _error(fn):
    """The ClientError fn() raised (Code, Message). A success is never an error: it raises instead."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    resp.pop("ResponseMetadata", None)
    raise AssertionError(f"call was expected to be refused but succeeded: {resp!r}")


def _create_identity_pool(ci, ctx, provider, client_id):
    pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-unsigned-pool-").replace("-", "_"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[{
            "ProviderName": provider, "ClientId": client_id, "ServerSideTokenCheck": False,
        }],
        IdentityPoolTags={"sim2real": GROUP},
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=pool_id))
    return pool_id


def _create_user_pool(ctx):
    """A real user pool + app client: Cognito Identity rejects fabricated provider tokens."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-unsigned-up-"), UserPoolTags={"sim2real": GROUP},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName="sim2real-unsigned-client",
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    return idp, pool_id, client_id


def _mint_id_token(idp, ctx, pool_id, client_id):
    username = ctx.unique_name("sim2real-unsigned-user-")
    password = "Sim2Real!" + uuid.uuid4().hex[:12]
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True,
    )
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["IdToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
