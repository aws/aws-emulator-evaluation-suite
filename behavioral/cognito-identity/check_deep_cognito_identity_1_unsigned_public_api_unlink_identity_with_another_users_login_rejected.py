"""deep-cognito-identity-1-unsigned-public-api-unlink-identity-with-another-users-login-rejected."""
from __future__ import annotations

import uuid

from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-identity-1-unsigned-public-api-unlink-identity-with-another-users-login-rejected"
GROUP = "unsigned-public-api"
SERVICES = ["cognito-identity"]

# On real Cognito Identity, an UNSIGNED UnlinkIdentity on user
# A's identity, carrying a perfectly valid token for user B from the same provider, is refused
# NotAuthorizedException ("Logins don't match ..."), and A's link is untouched.
ERR_NOT_AUTHORIZED = "NotAuthorizedException"
MSG_LOGINS_DONT_MATCH = (
    "Logins don't match. Please include at least one valid login for this identity or identity pool."
)
DISABLED = "DISABLED"


@tags("dp:api", "plane:data", "concern:negative-classes", "axis:rejection", "cap:c1")
def run(ctx) -> None:
    """An unsigned UnlinkIdentity presenting another user's valid token is refused and leaves the
    victim's link intact, while the same unsigned call with the owner's own token succeeds."""
    signed = ctx.client("cognito-identity")
    unsigned = ctx.client("cognito-identity", config=Config(signature_version=UNSIGNED))

    idp, user_pool_id, client_id = _create_user_pool(ctx)
    provider = f"cognito-idp.{ctx.region}.amazonaws.com/{user_pool_id}"
    token_a = _mint_id_token(idp, ctx, user_pool_id, client_id)
    token_b = _mint_id_token(idp, ctx, user_pool_id, client_id)
    pool_id = _create_identity_pool(signed, ctx, provider, client_id)

    id_a = unsigned.get_id(IdentityPoolId=pool_id, Logins={provider: token_a})["IdentityId"]
    id_b = unsigned.get_id(IdentityPoolId=pool_id, Logins={provider: token_b})["IdentityId"]
    assert id_a != id_b, f"two different users resolved to the same identity {id_a!r}"

    err = _error(lambda: unsigned.unlink_identity(
        IdentityId=id_a, Logins={provider: token_b}, LoginsToRemove=[provider],
    ))
    assert (err.get("Code"), err.get("Message")) == (ERR_NOT_AUTHORIZED, MSG_LOGINS_DONT_MATCH), (
        f"unsigned UnlinkIdentity of A with B's token answered {err!r}, expected "
        f"{ERR_NOT_AUTHORIZED!r}: {MSG_LOGINS_DONT_MATCH!r}"
    )

    # Effect absent: A is still linked, and A's login still resolves to A.
    still = signed.describe_identity(IdentityId=id_a).get("Logins")
    assert still == [provider], f"after the refused unlink A lists {still!r}, expected [{provider!r}]"
    resolved = unsigned.get_id(IdentityPoolId=pool_id, Logins={provider: token_a})["IdentityId"]
    assert resolved == id_a, (
        f"after the refused unlink A's login resolves to {resolved!r}, expected {id_a!r}"
    )

    # Positive control: the owner's own token, same unsigned client, same identity.
    resp = unsigned.unlink_identity(
        IdentityId=id_a, Logins={provider: token_a}, LoginsToRemove=[provider],
    )
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"unsigned UnlinkIdentity with A's own token returned HTTP {status!r}"
    gone = signed.describe_identity(IdentityId=id_a).get("Logins")
    assert gone == [DISABLED], f"after the owner's unlink A lists {gone!r}, expected [{DISABLED!r}]"
    b_logins = signed.describe_identity(IdentityId=id_b).get("Logins")
    assert b_logins == [provider], (
        f"unlinking A changed B's identity to {b_logins!r}, expected [{provider!r}]"
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
