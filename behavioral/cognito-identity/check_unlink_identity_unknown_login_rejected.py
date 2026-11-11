"""unlink-identity-unknown-login-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unlink-identity-unknown-login-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-identity"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UnlinkIdentity without credentials is refused with NotAuthorizedException "Access to Identity
    '<id>' is forbidden." and leaves the identity's login linked; the same removal with a valid
    token for that login unlinks it, leaving Logins ["DISABLED"]."""
    region = ctx.region
    cidp = ctx.client("cognito-idp")
    ci = ctx.client("cognito-identity")

    pool_id, client_id, username, password = _create_confirmed_user_pool_user(ctx, cidp)
    provider_name = f"cognito-idp.{region}.amazonaws.com/{pool_id}"
    auth = cidp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    id_token = auth["AuthenticationResult"]["IdToken"]

    ci_pool_id = ci.create_identity_pool(
        IdentityPoolName=ctx.unique_name("sim2real-cipool-"),
        AllowUnauthenticatedIdentities=True,
        CognitoIdentityProviders=[
            {"ProviderName": provider_name, "ClientId": client_id, "ServerSideTokenCheck": False}
        ],
    )["IdentityPoolId"]
    ctx.on_cleanup(lambda: ci.delete_identity_pool(IdentityPoolId=ci_pool_id))

    logins = {provider_name: id_token}
    identity_id = ci.get_id(IdentityPoolId=ci_pool_id, Logins=logins)["IdentityId"]
    described = ci.describe_identity(IdentityId=identity_id)
    assert described["Logins"] == [provider_name], (
        f"expected the identity to carry its real linked provider, got {described.get('Logins')!r}"
    )

    # For a linked identity, UnlinkIdentity without Logins answers NotAuthorizedException with a
    # message naming the identity, distinct from "Cannot unlink unauthenticated user." for an
    # identity that never authenticated.
    forbidden_msg = f"Access to Identity '{identity_id}' is forbidden."

    # Break exactly one thing: supply no Logins at all, while naming an unrelated,
    # never-linked provider in LoginsToRemove.
    code, message = _error(
        lambda: ci.unlink_identity(
            IdentityId=identity_id, Logins={}, LoginsToRemove=["graph.facebook.com"]
        )
    )
    assert code == "NotAuthorizedException", f"CODE={code} MESSAGE={message!r}"
    assert message == forbidden_msg, f"MESSAGE={message!r}"

    # Effect absent: the real linked login is untouched by the rejected call.
    described_after = ci.describe_identity(IdentityId=identity_id)
    assert described_after["Logins"] == [provider_name], (
        f"a rejected UnlinkIdentity must not touch the real login, got "
        f"{described_after.get('Logins')!r}"
    )

    # The rejection is not about the unknown provider in LoginsToRemove: an empty LoginsToRemove,
    # still without Logins, is rejected identically.
    code, message = _error(
        lambda: ci.unlink_identity(IdentityId=identity_id, Logins={}, LoginsToRemove=[])
    )
    assert code == "NotAuthorizedException", f"CODE={code} MESSAGE={message!r}"
    assert message == forbidden_msg, f"MESSAGE={message!r}"

    # Positive control / restore: the identical removal, correctly authenticated,
    # succeeds -- proving the earlier rejections were about the missing Logins, not
    # about UnlinkIdentity being universally refused for this identity.
    ci.unlink_identity(IdentityId=identity_id, Logins=logins, LoginsToRemove=[provider_name])
    final = ci.describe_identity(IdentityId=identity_id)
    assert final["Logins"] == ["DISABLED"], (
        f"a successful unlink must replace the linked provider with the DISABLED "
        f"sentinel, got {final.get('Logins')!r}"
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


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message") or ""
    raise AssertionError("expected UnlinkIdentity to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
